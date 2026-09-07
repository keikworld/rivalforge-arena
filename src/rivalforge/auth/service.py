"""The one entry point for connecting a wallet.

Everything a caller needs is here, so a Telegram handler, an HTTP route and the
CLI cannot each invent their own slightly-different flow. The previous codebase
had 45 handler modules reaching directly into services, and that is how one of
them ends up skipping a check the others make.

The flow, and what each step guarantees:

    begin(wallet)   -> a single-use challenge to sign
    complete(nonce, signature)
                    -> proof of key control, a session, and an audit record
    fighters(token) -> the NFTs that session's wallet actually holds

`complete` is the only place in this codebase where a signature becomes an
identity, and `fighters` is the only place ownership gates play.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Final, Sequence

from ..content.schema import GameContent
from ..engine.fighter import Fighter, derive_fighter
from ..plugins.ports import NFTOwnershipProvider, OwnedNFT
from ..security.redaction import short_address
from ..security.validation import ValidationError, validate_mint_address
from .audit import AuditEvent, AuditTrail
from .challenge import AuthError, Challenge, ChallengeService
from .session import IssuedSession, SessionService
from .store import RateLimitExceeded

logger = logging.getLogger(__name__)

__all__ = ["WalletService", "ConnectedWallet", "OwnershipRequired"]

#: Cap on how many NFTs one wallet's roster will render. A collector with
#: thousands must not be able to make one request expensive for everyone.
MAX_ROSTER: Final = 50


class OwnershipRequired(Exception):
    """The session's wallet does not hold the NFT it tried to play.

    Distinct from `AuthError`: the caller *is* authenticated, they simply do not
    own this asset. Conflating the two would make a legitimate "pick something
    else" look like a login failure.
    """


@dataclass(frozen=True, slots=True)
class ConnectedWallet:
    """The result of a completed connection."""

    wallet: str
    token: str
    expires_at: object

    @property
    def short_wallet(self) -> str:
        return short_address(self.wallet)


class WalletService:
    """Wallet connection, ownership gating, and the audit trail around both."""

    def __init__(
        self,
        challenges: ChallengeService,
        sessions: SessionService,
        ownership: NFTOwnershipProvider,
        audit: AuditTrail,
        content: GameContent,
        *,
        require_ownership: bool = True,
    ) -> None:
        self._challenges = challenges
        self._sessions = sessions
        self._ownership = ownership
        self._audit = audit
        self._content = content
        self._require_ownership = require_ownership

    # -- connecting ------------------------------------------------------

    def begin(self, wallet: str) -> Challenge:
        """Start a connection. Returns the text to sign.

        Raises:
            ValidationError: the address is malformed.
            RateLimitExceeded: too many live challenges for this wallet.
        """
        try:
            validate_mint_address(wallet, field="wallet")
        except ValidationError:
            # Not audited by wallet, because there is no valid wallet to name.
            raise

        try:
            challenge = self._challenges.issue(wallet)
        except RateLimitExceeded:
            self._audit.challenge_rate_limited(wallet)
            raise

        self._audit.challenge_issued(wallet)
        logger.info("challenge issued for %s", short_address(wallet))
        return challenge

    def complete(self, nonce: str, signature: str) -> ConnectedWallet:
        """Finish a connection by proving control of the key.

        Raises:
            AuthError: with a single generic message for every failure mode.
        """
        try:
            result = self._challenges.verify(nonce, signature)
        except AuthError as exc:
            # The specific reason goes to the audit trail and the log; the
            # caller gets the generic message only.
            self._audit.auth_failed(None, exc.internal_reason)
            logger.info("authentication failed: %s", exc.internal_reason)
            raise

        issued: IssuedSession = self._sessions.issue(result.wallet)
        self._audit.auth_succeeded(result.wallet)
        logger.info("wallet connected: %s", short_address(result.wallet))
        return ConnectedWallet(
            wallet=result.wallet,
            token=issued.token,
            expires_at=issued.session.expires_at,
        )

    def disconnect(self, token: str) -> bool:
        """End a session. True if one was ended."""
        # Resolve before revoking, so the audit record can name the wallet.
        session = self._sessions.resolve(token)
        ended = self._sessions.revoke(token)
        if ended and session is not None:
            self._audit.record(
                AuditEvent.SESSION_REVOKED, wallet=session.wallet, outcome="ok"
            )
        return ended

    # -- using a connection ----------------------------------------------

    def wallet_for(self, token: str) -> str:
        """The wallet behind a session token.

        Raises:
            AuthError: if the token is unknown, malformed or expired. All three
                are one message, because the caller has no legitimate use for
                the difference.
        """
        session = self._sessions.resolve(token)
        if session is None:
            raise AuthError("no live session for this token")
        return session.wallet

    def roster(self, token: str, *, limit: int = 20) -> Sequence[OwnedNFT]:
        """The NFTs held by this session's wallet.

        Raises:
            AuthError: no live session.
            RuntimeError: the ownership provider could not answer. An outage is
                surfaced rather than silently returning an empty roster, which
                would look to a player like "your NFTs are gone".
        """
        wallet = self.wallet_for(token)
        limit = max(1, min(int(limit), MAX_ROSTER))
        try:
            return self._ownership.list_owned(wallet, limit=limit)
        except Exception as exc:
            logger.warning("roster unavailable for %s", short_address(wallet))
            raise RuntimeError(f"could not read holdings: {exc}") from exc

    def fighter_for(self, token: str, mint: str, *, name: str | None = None) -> Fighter:
        """Build the fighter for `mint`, after checking this wallet holds it.

        This is the gate. Ownership is checked here, on every use, rather than
        being trusted from an earlier check -- an NFT can be sold between one
        match and the next.

        Raises:
            AuthError: no live session.
            ValidationError: the mint is malformed.
            OwnershipRequired: the wallet does not hold it, or ownership could
                not be established. **Unavailable fails closed**: if we cannot
                confirm ownership we do not grant it. That is the opposite of
                the rule for *reading* a roster, and deliberately so -- refusing
                to check is not permission.
        """
        wallet = self.wallet_for(token)
        validate_mint_address(mint, field="mint")

        if not self._require_ownership:
            logger.warning("ownership enforcement is OFF; granting %s", short_address(mint))
            return derive_fighter(mint, self._content, name=name)

        result = self._ownership.verify_ownership(wallet, mint)
        self._audit.ownership(wallet, mint, result)

        if not result.verified:
            if result.checked:
                raise OwnershipRequired("this wallet does not hold that NFT")
            raise OwnershipRequired(
                "ownership could not be confirmed right now; try again shortly"
            )
        return derive_fighter(mint, self._content, name=name)
