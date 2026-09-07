"""Ports: the interfaces the game depends on, and nothing more.

Ports-and-adapters, applied strictly. The game core depends only on the
protocols below. Every concrete thing -- Helius, a Postgres database, Telegram
Stars, an LLM -- is an adapter registered in `plugins.registries` and selected
by configuration.

The rule that makes it work: **nothing below `plugins/` may import an adapter.**
The core imports the port; the wiring layer picks the adapter. That is what
makes a provider swappable without touching a call site, and it is the single
biggest structural difference from the previous codebase, where replacing the
RPC layer would have meant editing thirty files.

These are `typing.Protocol`s, so an adapter does not inherit anything. It just
has the right methods. A third-party package can satisfy a port without
importing this module at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

__all__ = [
    "OwnedNFT",
    "OwnershipResult",
    "NFTOwnershipProvider",
    "Clock",
    "KeyValueStore",
    "PlayerRecord",
    "PlayerStore",
    "Notifier",
    "PaymentProvider",
    "PaymentIntent",
]


# --------------------------------------------------------------------------
# Wallet / NFT ownership
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OwnedNFT:
    """One NFT held by a wallet.

    Deliberately minimal. The game needs an identifier, something to show, and
    the collection it belongs to. Anything richer is provider-specific and
    belongs in the adapter, not in a shape the core depends on.
    """

    mint: str
    name: str
    collection: str | None
    image_url: str | None = None

    @property
    def short_mint(self) -> str:
        if len(self.mint) <= 11:
            return self.mint
        return f"{self.mint[:4]}...{self.mint[-4:]}"


@dataclass(frozen=True, slots=True)
class OwnershipResult:
    """The answer to "does this wallet hold this NFT right now?".

    Three states, not two. `verified=False, reason=...` for a definite no, and
    `checked=False` for "the provider could not tell us" -- a timeout, a rate
    limit, an outage.

    Collapsing those two into one boolean is how a game bans players during an
    RPC outage. The caller must be able to distinguish "you do not own this"
    from "we could not check", because the right response differs: refuse in
    the first case, degrade gracefully in the second.
    """

    verified: bool
    checked: bool = True
    reason: str = ""

    @classmethod
    def owned(cls) -> "OwnershipResult":
        return cls(verified=True)

    @classmethod
    def not_owned(cls, reason: str = "wallet does not hold this NFT") -> "OwnershipResult":
        return cls(verified=False, reason=reason)

    @classmethod
    def unavailable(cls, reason: str) -> "OwnershipResult":
        """The provider could not answer. Not a denial."""
        return cls(verified=False, checked=False, reason=reason)


@runtime_checkable
class NFTOwnershipProvider(Protocol):
    """Reads NFT ownership from a chain, an indexer, or a fixture.

    Implementations must be read-only. Nothing in this port signs a transaction
    or moves an asset, so a compromised or malicious provider can lie about
    ownership but can never take anything.
    """

    name: str

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        """Whether `wallet` currently holds `mint`."""
        ...

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        """The NFTs `wallet` holds, newest or arbitrary order, capped."""
        ...


# --------------------------------------------------------------------------
# Infrastructure
# --------------------------------------------------------------------------


@runtime_checkable
class Clock(Protocol):
    """Wall-clock time, injected rather than imported.

    A daily arena rotation and a daily boss both hinge on "what day is it",
    and testing either against the real clock means either a test that fails
    at midnight or one that does not test the rotation at all.
    """

    def now(self) -> datetime:
        ...


@runtime_checkable
class KeyValueStore(Protocol):
    """A small durable map. Backed by memory, a file, Redis, or a table."""

    def get(self, key: str) -> str | None:
        ...

    def set(self, key: str, value: str, *, ttl_seconds: int | None = None) -> None:
        ...

    def delete(self, key: str) -> None:
        ...


@dataclass(frozen=True, slots=True)
class PlayerRecord:
    """What persists about a player between sessions.

    `wallet` is optional throughout: a player must be able to exist, fight and
    appear on a ladder before ever connecting one.
    """

    player_id: str
    display_name: str
    wallet: str | None
    points: int
    wins: int
    losses: int
    created_at: datetime
    metadata: Mapping[str, Any] | None = None


@runtime_checkable
class PlayerStore(Protocol):
    """Persistence for players and their ladder position."""

    name: str

    def get_player(self, player_id: str) -> PlayerRecord | None:
        ...

    def upsert_player(self, record: PlayerRecord) -> PlayerRecord:
        ...

    def record_result(self, player_id: str, *, won: bool, points_delta: int) -> PlayerRecord:
        ...

    def leaderboard(self, *, limit: int = 50) -> Sequence[PlayerRecord]:
        ...


@runtime_checkable
class Notifier(Protocol):
    """Sends a message to a player. Telegram, email, a websocket, a log line."""

    name: str

    def notify(self, player_id: str, message: str) -> bool:
        ...


# --------------------------------------------------------------------------
# Money
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PaymentIntent:
    """A request for payment, before it is settled."""

    intent_id: str
    player_id: str
    amount_minor: int
    currency: str
    description: str
    metadata: Mapping[str, Any] | None = None


@runtime_checkable
class PaymentProvider(Protocol):
    """Takes payment. Telegram Stars, Solana Pay, a card processor, a stub.

    Two methods and no refund path on purpose: a provider that can charge is
    already the highest-risk adapter in the system, and every capability it is
    given is one an attacker inherits if it is compromised. Refunds are
    deliberately an out-of-band, human-approved operation for now.
    """

    name: str

    def create_intent(
        self, player_id: str, amount_minor: int, currency: str, description: str
    ) -> PaymentIntent:
        ...

    def is_settled(self, intent_id: str) -> bool:
        ...
