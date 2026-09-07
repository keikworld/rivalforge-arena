"""Where challenges live between issue and verify.

The single property that matters here is that `consume` is **atomic
get-and-delete**. Replay protection is not implemented in the verifier; it is
implemented here. A store whose `consume` were a read followed by a separate
delete would let two concurrent requests both succeed with one nonce.

The store is also an unauthenticated entry point: anyone who can reach `issue`
can fill it. So it is bounded, it evicts, and it rate-limits per wallet.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Final, Protocol, runtime_checkable

from ..plugins.registry import Registry

logger = logging.getLogger(__name__)

__all__ = [
    "ChallengeStore",
    "InMemoryChallengeStore",
    "CHALLENGE_STORES",
    "RateLimitExceeded",
    "MAX_CHALLENGES",
    "MAX_PER_WALLET",
]

#: Hard ceiling on stored challenges. Reached only under abuse; the oldest are
#: evicted rather than the process running out of memory.
MAX_CHALLENGES: Final = 10_000

#: Concurrent live challenges for one wallet. A player needs one at a time;
#: anything beyond a handful is someone probing.
MAX_PER_WALLET: Final = 5


class RateLimitExceeded(Exception):
    """Too many challenges requested for one wallet.

    Separate from `AuthError` because it is not an authentication failure and
    the caller should back off rather than retry.
    """


@runtime_checkable
class ChallengeStore(Protocol):
    """Storage for pending challenges."""

    def put(self, challenge) -> None:
        """Store a challenge. Raises `RateLimitExceeded` past the per-wallet cap."""
        ...

    def consume(self, nonce: str):
        """Atomically fetch and remove. Returns the challenge or None."""
        ...

    def purge_expired(self, now: datetime) -> int:
        """Drop expired challenges. Returns how many went."""
        ...

    def __len__(self) -> int:
        ...


CHALLENGE_STORES: Registry[type] = Registry(
    "challenge store", "rivalforge.challenge_stores"
)


@CHALLENGE_STORES.register("memory")
class InMemoryChallengeStore:
    """A bounded, thread-safe, self-evicting challenge store.

    Correct for a single process. Multi-process deployments need a shared store
    (Redis or Postgres) or two workers will not see each other's nonces --
    which fails closed, as a rejected login rather than an accepted one.
    """

    name = "memory"

    __slots__ = ("_by_nonce", "_by_wallet", "_lock", "_max", "_max_per_wallet")

    def __init__(
        self, *, max_challenges: int = MAX_CHALLENGES, max_per_wallet: int = MAX_PER_WALLET
    ) -> None:
        if max_challenges < 1 or max_per_wallet < 1:
            raise ValueError("limits must be positive")
        self._by_nonce: dict[str, object] = {}
        self._by_wallet: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._max = max_challenges
        self._max_per_wallet = max_per_wallet

    def put(self, challenge) -> None:
        with self._lock:
            live = self._by_wallet.get(challenge.wallet, set())
            # Count only unexpired ones, so a player who abandoned a few
            # prompts is not locked out until they time out.
            live = {n for n in live if not self._expired_locked(n, challenge.issued_at)}
            if len(live) >= self._max_per_wallet:
                raise RateLimitExceeded(
                    f"more than {self._max_per_wallet} live challenges for this wallet"
                )

            if len(self._by_nonce) >= self._max:
                self._evict_oldest_locked()

            self._by_nonce[challenge.nonce] = challenge
            live.add(challenge.nonce)
            self._by_wallet[challenge.wallet] = live

    def _expired_locked(self, nonce: str, now: datetime) -> bool:
        stored = self._by_nonce.get(nonce)
        return stored is None or stored.is_expired(now)

    def _evict_oldest_locked(self) -> None:
        """Drop the challenge closest to expiry.

        Evicting the *oldest* rather than a random one means an attacker
        flooding the store pushes out their own filler first, and a legitimate
        player's fresh challenge survives longest.
        """
        if not self._by_nonce:
            return
        oldest = min(self._by_nonce.items(), key=lambda kv: kv[1].expires_at)[0]
        self._forget_locked(oldest)

    def _forget_locked(self, nonce: str) -> object | None:
        challenge = self._by_nonce.pop(nonce, None)
        if challenge is not None:
            nonces = self._by_wallet.get(challenge.wallet)
            if nonces is not None:
                nonces.discard(nonce)
                if not nonces:
                    del self._by_wallet[challenge.wallet]
        return challenge

    def consume(self, nonce: str):
        """Atomic get-and-delete. The replay defence lives here."""
        with self._lock:
            return self._forget_locked(nonce)

    def purge_expired(self, now: datetime) -> int:
        with self._lock:
            stale = [n for n, c in self._by_nonce.items() if c.is_expired(now)]
            for nonce in stale:
                self._forget_locked(nonce)
            return len(stale)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_nonce)

    def live_for(self, wallet: str) -> int:
        """How many challenges are outstanding for one wallet. For tests."""
        with self._lock:
            return len(self._by_wallet.get(wallet, ()))
