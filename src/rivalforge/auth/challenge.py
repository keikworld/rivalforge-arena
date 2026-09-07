"""Wallet authentication by message signature.

# Why this cannot drain a wallet

This is the most security-sensitive module in the codebase, so the guarantee is
stated first and everything below serves it.

**We never request a transaction signature, and we never touch key material.**

* We ask the player's wallet to sign a short block of *human-readable text*.
  A message signature moves nothing. It authorises no transfer, no delegation,
  no token approval and no program invocation.
* We never ask for, receive, store, transmit or log a private key or a seed
  phrase. No key material enters this process at any point.
* We never construct, request or relay a Solana transaction. There is no code
  path in this repository that can build one.

There is one real attack in this area worth naming, because "we only sign
messages" is not by itself sufficient: a hostile site can ask a wallet to sign
bytes that are secretly a *serialised transaction*, and a wallet that signs
blindly would then have signed a transfer. The defence is that our message is
constrained to printable text beginning with the domain name
(`_assert_not_transaction_shaped`), and a Solana transaction's first byte is a
small signature count, never a printable character. The constraint is enforced
at construction and asserted in the tests.

# The flow

1.  `issue()` mints a single-use, short-lived, wallet-bound challenge and
    stores it server-side.
2.  The player signs the challenge text in their wallet.
3.  `verify()` looks the challenge up **by nonce**, rebuilds the message from
    *server-held* state, checks the signature against it, and atomically
    consumes the nonce.

Step 3 is where implementations usually go wrong. The message that is verified
is the one the server stored, never one the client supplied. A verifier that
checks a client-supplied message proves only that the client can sign something
it chose, which is no proof of anything.
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

from ..security.validation import (
    ValidationError,
    b58decode,
    validate_mint_address,
)
from .store import ChallengeStore

logger = logging.getLogger(__name__)

__all__ = [
    "Challenge",
    "AuthResult",
    "ChallengeService",
    "AuthError",
    "CHALLENGE_TTL",
    "build_message",
]

#: Long enough for a person to read the prompt and press a button; short enough
#: that a captured challenge is worthless by the time it is exfiltrated.
CHALLENGE_TTL: Final = timedelta(minutes=5)

#: 256 bits. The nonce is the whole replay defence, so it is generated with
#: `secrets` and never derived from anything predictable.
_NONCE_BYTES: Final = 32

#: An ed25519 signature is exactly 64 bytes and a public key exactly 32.
_SIGNATURE_BYTES: Final = 64
_PUBKEY_BYTES: Final = 32

#: Clock skew allowance. A player's device being a few seconds fast must not
#: make a freshly issued challenge unusable.
_SKEW: Final = timedelta(seconds=30)

_PRINTABLE = re.compile(r"^[\x20-\x7E\n]+$")


class AuthError(Exception):
    """Authentication failed.

    Deliberately carries a *generic* public message. The internal reason is
    logged, never returned: distinguishing "no such nonce" from "wrong wallet"
    from "expired" hands an attacker an oracle for enumerating state.
    """

    PUBLIC_MESSAGE: Final = "authentication failed"

    def __init__(self, internal_reason: str) -> None:
        self.internal_reason = internal_reason
        super().__init__(self.PUBLIC_MESSAGE)


@dataclass(frozen=True, slots=True)
class Challenge:
    """A single-use, wallet-bound, expiring authentication challenge."""

    nonce: str
    wallet: str
    domain: str
    uri: str
    cluster: str
    issued_at: datetime
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now > self.expires_at

    @property
    def message(self) -> str:
        """The exact text the wallet is asked to sign."""
        return build_message(self)


@dataclass(frozen=True, slots=True)
class AuthResult:
    """A successful authentication. Carries no secret."""

    wallet: str
    authenticated_at: datetime
    nonce: str


def build_message(challenge: Challenge) -> str:
    """Render the challenge as the text a wallet will display.

    Modelled on Sign-In With Solana. Two properties matter more than the exact
    wording:

    * it opens with the domain, so a player can see who is asking and a
      signature captured by one site cannot be replayed against another;
    * it says plainly that it is not a transaction, because the player reading
      their wallet prompt is the last line of defence and deserves a sentence
      they can actually act on.
    """
    return (
        f"{challenge.domain} wants you to sign in with your Solana account:\n"
        f"{challenge.wallet}\n"
        f"\n"
        f"This is a signature request only. It does not move funds, approve\n"
        f"transfers, or give this site access to your assets.\n"
        f"\n"
        f"URI: {challenge.uri}\n"
        f"Version: 1\n"
        f"Chain: solana:{challenge.cluster}\n"
        f"Nonce: {challenge.nonce}\n"
        f"Issued At: {challenge.issued_at.isoformat()}\n"
        f"Expiration Time: {challenge.expires_at.isoformat()}"
    )


def _assert_not_transaction_shaped(message: str) -> None:
    """Refuse to ask anyone to sign anything that could be a transaction.

    A Solana transaction begins with a compact-u16 signature count -- a byte in
    the range 1..255, which is not a printable ASCII character. Constraining the
    message to printable ASCII that starts with a letter or digit means the
    bytes we hand a wallet cannot deserialise as a transaction.

    This is belt and braces on top of "we never build transactions", and it is
    cheap. The expensive version of this lesson is someone's wallet.
    """
    if not message or not _PRINTABLE.match(message):
        raise ValueError("challenge message must be printable ASCII")
    if not message[0].isalnum():
        raise ValueError("challenge message must begin with an alphanumeric character")


class ChallengeService:
    """Issues and verifies wallet-signature challenges.

    Args:
        store: Where challenges live between issue and verify. The store's
            `consume` must be atomic -- that is what makes replay impossible
            under concurrency, not anything in this class.
        clock: Injected so expiry is testable without waiting.
        domain: The name shown to the player and bound into the signature.
        uri: The canonical URI for this deployment.
        cluster: `mainnet`, `devnet`, ...
        ttl: How long a challenge stays valid.
    """

    def __init__(
        self,
        store: ChallengeStore,
        clock,
        *,
        domain: str,
        uri: str,
        cluster: str = "mainnet",
        ttl: timedelta = CHALLENGE_TTL,
    ) -> None:
        if not domain or not _PRINTABLE.match(domain) or " " in domain:
            raise ValueError(f"invalid domain: {domain!r}")
        if not uri or not _PRINTABLE.match(uri) or " " in uri:
            raise ValueError(f"invalid uri: {uri!r}")
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        self._store = store
        self._clock = clock
        self._domain = domain
        self._uri = uri
        self._cluster = cluster
        self._ttl = ttl

    @property
    def domain(self) -> str:
        return self._domain

    def issue(self, wallet: str) -> Challenge:
        """Mint a challenge for `wallet`.

        Raises:
            ValidationError: if the wallet is not a well-formed address. Checked
                before anything is stored, so a malformed value cannot occupy
                store capacity.
        """
        validate_mint_address(wallet, field="wallet")

        now = self._clock.now()
        if now.tzinfo is None:  # a naive clock would break every comparison
            now = now.replace(tzinfo=timezone.utc)

        challenge = Challenge(
            nonce=secrets.token_hex(_NONCE_BYTES),
            wallet=wallet,
            domain=self._domain,
            uri=self._uri,
            cluster=self._cluster,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        # Fail before storing if the rendered text is anything but safe.
        _assert_not_transaction_shaped(challenge.message)
        self._store.put(challenge)
        return challenge

    def verify(self, nonce: str, signature: str) -> AuthResult:
        """Verify a signature against the stored challenge for `nonce`.

        Args:
            nonce: Identifies which challenge is being answered.
            signature: Base58-encoded 64-byte ed25519 signature, as every
                Solana wallet produces.

        Returns:
            An `AuthResult` naming the wallet that proved control of its key.

        Raises:
            AuthError: for every failure, with one generic public message. The
                specific reason is logged and never returned.

        The nonce is consumed **before** the signature is checked. A failed
        attempt therefore burns the challenge, so an attacker cannot grind
        signatures against one live nonce.
        """
        if not isinstance(nonce, str) or not nonce:
            raise AuthError("nonce missing or not a string")
        if not isinstance(signature, str) or not signature:
            raise AuthError("signature missing or not a string")

        # Bound the inputs before doing any work with them.
        if len(nonce) > 128 or len(signature) > 256:
            raise AuthError("oversized nonce or signature")

        now = self._clock.now()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        # Atomic get-and-delete: single use, even under concurrency.
        challenge = self._store.consume(nonce)
        if challenge is None:
            raise AuthError("no such nonce, or already used")

        if challenge.is_expired(now):
            raise AuthError("challenge expired")
        if challenge.issued_at - _SKEW > now:
            raise AuthError("challenge issued in the future")

        # Bind to this deployment. A challenge minted for another domain must
        # not authenticate here even if the store were somehow shared.
        if not hmac.compare_digest(challenge.domain, self._domain):
            raise AuthError("domain mismatch")

        try:
            signature_bytes = b58decode(signature)
        except ValidationError:
            raise AuthError("signature is not valid base58") from None
        if len(signature_bytes) != _SIGNATURE_BYTES:
            raise AuthError(f"signature is {len(signature_bytes)} bytes, expected 64")

        try:
            public_key = b58decode(challenge.wallet)
        except ValidationError:  # pragma: no cover - validated at issue time
            raise AuthError("stored wallet is not valid base58") from None
        if len(public_key) != _PUBKEY_BYTES:  # pragma: no cover - ditto
            raise AuthError("stored wallet is not a 32-byte key")

        # The message verified is the one rebuilt from *server-held* state.
        # Never a client-supplied string: that would prove only that the caller
        # can sign something of its own choosing.
        message_bytes = challenge.message.encode("utf-8")

        if not _verify_ed25519(public_key, message_bytes, signature_bytes):
            raise AuthError("signature does not match")

        return AuthResult(
            wallet=challenge.wallet, authenticated_at=now, nonce=challenge.nonce
        )


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an ed25519 signature.

    Delegated to libsodium via PyNaCl. Hand-rolled curve arithmetic is how
    signature-verification bugs get written, and a verifier that accepts a
    forged signature is worse than no verifier at all.
    """
    try:
        from nacl.exceptions import BadSignatureError  # noqa: PLC0415
        from nacl.signing import VerifyKey  # noqa: PLC0415
    except ImportError:  # pragma: no cover - guarded at start-up
        raise AuthError("signature verification is unavailable") from None

    try:
        VerifyKey(public_key).verify(message, signature)
    except BadSignatureError:
        return False
    except Exception:
        # A malformed key or signature must be a clean "no", never a crash that
        # takes down the endpoint. This is an entry point.
        logger.debug("signature verification raised", exc_info=True)
        return False
    return True
