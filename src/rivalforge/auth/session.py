"""Sessions issued after a wallet proves control of its key.

Design points, each of which is a control rather than a preference:

*   **Tokens are stored hashed, never in plaintext.** A dump of the session
    table must not hand the reader a set of live sessions. We store
    SHA-256(token); the token itself exists only in the holder's hands.
*   **Tokens are 256 bits from `secrets`.** Guessing is not a threat model we
    need to reason about further.
*   **Lookup is by hash, so it is constant-time by construction.** There is no
    string comparison against a stored secret to get wrong.
*   **Sessions expire, and expiry is checked on every read.** A session is not
    an identity; it is a short-lived assertion that an identity was proved
    recently.
*   **A session carries only the wallet.** Not an IP, not a user agent, not a
    device fingerprint. None of those improve the security of this design and
    all of them are data we would then have to protect.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Final

from .session_store import InMemorySessionStore, SessionStore

logger = logging.getLogger(__name__)

__all__ = ["Session", "SessionService", "SESSION_TTL", "MAX_SESSIONS"]

#: Long enough to play without re-signing; short enough that a leaked token is
#: not a standing key to an account.
SESSION_TTL: Final = timedelta(hours=12)

#: Bound on stored sessions, so an attacker who can authenticate repeatedly
#: cannot grow memory without limit.
MAX_SESSIONS: Final = 50_000

_TOKEN_BYTES: Final = 32


def _hash_token(token: str) -> str:
    """SHA-256 of the token, hex. What we store; never the token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Session:
    """A live session. Holds the token *hash*, never the token."""

    token_hash: str
    wallet: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now > self.expires_at


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """What `issue` hands back: the session plus the one-time plaintext token.

    The token appears here and nowhere else. It is never stored, never logged,
    and never returned again -- a caller that loses it must re-authenticate.
    """

    token: str
    session: Session


class SessionService:
    """Issues, validates and revokes sessions.

    Storage is a pluggable `SessionStore`, because the right backend differs by
    deployment: memory for tests, a file for the CLI (where `connect` and
    `play` are separate processes), Postgres for many workers. The service
    holds the policy -- hashing, expiry, bounds -- and the store holds only the
    bytes, so a new backend cannot accidentally change the security rules.
    """

    __slots__ = ("_store", "_clock", "_ttl", "_max")

    def __init__(
        self,
        clock,
        *,
        store: SessionStore | None = None,
        ttl: timedelta = SESSION_TTL,
        max_sessions: int = MAX_SESSIONS,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        self._store = store if store is not None else InMemorySessionStore()
        self._clock = clock
        self._ttl = ttl
        self._max = max_sessions

    def _now(self) -> datetime:
        now = self._clock.now()
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)

    def issue(self, wallet: str) -> IssuedSession:
        """Start a session for an already-authenticated wallet.

        This method does **not** authenticate. It is called only after
        `ChallengeService.verify` has returned, and giving it no ability to
        authenticate is deliberate: there is exactly one place in this codebase
        where a signature turns into an identity.
        """
        now = self._now()
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session = Session(
            token_hash=_hash_token(token),
            wallet=wallet,
            created_at=now,
            expires_at=now + self._ttl,
        )
        if len(self._store) >= self._max:
            self._store.purge_expired(now)
        if len(self._store) >= self._max:
            # Still full of live sessions: drop the one nearest expiry rather
            # than refuse a legitimate login.
            oldest = getattr(self._store, "oldest_token_hash", lambda: None)()
            if oldest is not None:
                self._store.delete(oldest)
        self._store.put(session)
        return IssuedSession(token=token, session=session)

    def resolve(self, token: str) -> Session | None:
        """The live session for `token`, or None.

        Returns None for unknown, malformed and expired tokens alike -- the
        caller has no legitimate use for the distinction, and offering it would
        be an oracle.
        """
        if not isinstance(token, str) or not token or len(token) > 512:
            return None
        digest = _hash_token(token)
        session = self._store.get(digest)
        if session is None:
            return None
        if session.is_expired(self._now()):
            # Expired sessions are removed on sight, so an abandoned session
            # does not linger until the next sweep.
            self._store.delete(digest)
            return None
        return session

    def revoke(self, token: str) -> bool:
        """End a session. True if one was ended."""
        if not isinstance(token, str) or not token:
            return False
        return self._store.delete(_hash_token(token))

    def revoke_wallet(self, wallet: str) -> int:
        """End every session for a wallet. For a player who suspects a leak."""
        return self._store.delete_wallet(wallet)

    def purge_expired(self) -> int:
        return self._store.purge_expired(self._now())

    def __len__(self) -> int:
        return len(self._store)
