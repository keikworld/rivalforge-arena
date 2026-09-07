"""The adapters that ship with the package.

Each implements a port from `ports.py` and registers itself. None of them is
imported by the game core -- the core asks a registry, and configuration
decides what comes back.

Every adapter here is either inert (`null`, `memory`, `fake`) or read-only
(`helius`). Nothing in this module can move an asset or spend money, which is
what makes it safe to ship enabled-by-default infrastructure with a game that
has not launched.

Security notes for the network adapter:

*   The API key is read from the environment, never a file in the repository,
    never a CLI argument (arguments are visible in `ps`), and never logged.
*   Every request carries a timeout, retries are bounded, and a circuit breaker
    drops a failing provider rather than hammering it.
*   Wallet and mint addresses are validated *before* a request is built, so a
    malformed value cannot be smuggled into a URL.
*   The provider is read-only. It answers questions about ownership; it holds
    no key and can sign nothing.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Final, Sequence

from ..security.redaction import short_address
from ..security.validation import (
    ValidationError,
    validate_mint_address,
)
from .ports import (
    OwnedNFT,
    OwnershipResult,
    PlayerRecord,
)
from .registries import CLOCKS, NOTIFIERS, PLAYER_STORES, WALLET_PROVIDERS
from .resilience import (
    CircuitBreaker,
    PermanentError,
    RetryPolicy,
    TransientError,
    call_with_retries,
)

logger = logging.getLogger(__name__)

__all__ = [
    "NullWalletProvider",
    "FakeWalletProvider",
    "DasWalletProvider",
    "HeliusWalletProvider",
    "SystemClock",
    "FixedClock",
    "MemoryPlayerStore",
    "NullNotifier",
]


# --------------------------------------------------------------------------
# Wallet providers
# --------------------------------------------------------------------------


@WALLET_PROVIDERS.register("null")
class NullWalletProvider:
    """Answers "I cannot check" to everything.

    The default, and the one used whenever `wallet_verification` is off. It
    reports `checked=False` rather than `verified=False`, which is the honest
    answer: nothing was checked. A caller that treated it as a denial would
    lock every player out the moment verification was disabled.
    """

    name = "null"

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        return OwnershipResult.unavailable("wallet verification is disabled")

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        return ()


class FakeWalletProvider:
    """An in-memory provider for tests and local play.

    Not registered by default -- it must be wired in explicitly, so it can
    never be selected in production by a stray environment variable.
    """

    name = "fake"

    def __init__(self, holdings: dict[str, list[OwnedNFT]] | None = None) -> None:
        self._holdings = holdings or {}

    def give(self, wallet: str, nft: OwnedNFT) -> None:
        self._holdings.setdefault(wallet, []).append(nft)

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        validate_mint_address(mint)
        held = {n.mint for n in self._holdings.get(wallet, ())}
        return OwnershipResult.owned() if mint in held else OwnershipResult.not_owned()

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        return tuple(self._holdings.get(wallet, ()))[:limit]


@WALLET_PROVIDERS.register("das")
class DasWalletProvider:
    """Reads Solana NFT ownership through the Metaplex DAS read API.

    One indexed `getAssetsByOwner` call per wallet, rather than the previous
    codebase's approach of enumerating token accounts and then fetching
    metadata for each -- that was O(n) RPC round trips for a wallet with n
    tokens, which for a collector never finishes inside a chat timeout.

    **No API key is required by default.** The public Solana mainnet RPC serves
    DAS, which was confirmed against the live endpoint: 289 assets returned for
    a test wallet with no credential. A key is supported for providers that
    want one (Helius among them) and simply raises the rate limit.

    Uses `urllib` rather than a client library on purpose: the engine has no
    runtime dependencies, and one POST of JSON does not justify the supply
    chain surface of an SDK.
    """

    name = "das"

    #: Public, keyless, DAS-capable. Verified working end to end.
    DEFAULT_ENDPOINT: Final = "https://api.mainnet-beta.solana.com"
    #: Per-request ceiling. A player is waiting on this inside a chat message,
    #: so a slow answer is worse than a graceful "could not check".
    DEFAULT_TIMEOUT: Final = 6.0
    MAX_PAGE: Final = 1000

    def __init__(
        self,
        api_key: str | None = None,
        *,
        endpoint: str | None = None,
        timeout: float | None = None,
        policy: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        opener: Any = None,
    ) -> None:
        # From the environment only. Never a CLI argument: those show up in
        # `ps` output and shell history.
        self._api_key = api_key or os.environ.get("RIVALFORGE_RPC_API_KEY", "") \
            or os.environ.get("HELIUS_API_KEY", "")
        self._endpoint = endpoint or os.environ.get(
            "RIVALFORGE_RPC_ENDPOINT", self.DEFAULT_ENDPOINT
        )
        self._timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT
        self._policy = policy or RetryPolicy(attempts=3, total_timeout=12.0)
        self._breaker = breaker or CircuitBreaker("helius", threshold=5, cooldown=30.0)
        self._opener = opener or urllib.request.urlopen

    @property
    def configured(self) -> bool:
        """Whether a call can be attempted.

        True whenever an endpoint is set. A key is optional: the default
        endpoint needs none, and an endpoint that does require one answers
        with a 401, which surfaces as a clear permanent failure rather than
        being pre-judged here.
        """
        return bool(self._endpoint)

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    # -- transport ----------------------------------------------------

    def _url(self) -> str:
        # Only append the credential when there is one. A bare `?api-key=` is
        # rejected by some providers and is noise in every access log.
        if not self._api_key:
            return self._endpoint
        return f"{self._endpoint}/?api-key={self._api_key}"

    def _post(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """One JSON-RPC call, with a hard timeout and typed failures."""
        body = json.dumps(
            {"jsonrpc": "2.0", "id": "rivalforge", "method": method, "params": params}
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url(),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with self._opener(request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # 4xx is our fault and will not fix itself; 5xx and 429 might.
            if exc.code in (429,) or exc.code >= 500:
                raise TransientError(f"provider returned HTTP {exc.code}") from exc
            raise PermanentError(f"provider rejected the request: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransientError(f"could not reach the provider: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise TransientError("provider returned a malformed response") from exc

        if "error" in payload:
            # The error body can echo request content; keep it out of the log.
            raise TransientError("provider reported an error")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise TransientError("provider returned an unexpected payload")
        return result

    def _fetch_page(self, wallet: str, page: int, limit: int) -> list[dict[str, Any]]:
        result = call_with_retries(
            lambda: self._post(
                "getAssetsByOwner",
                {
                    "ownerAddress": wallet,
                    "page": page,
                    "limit": min(limit, self.MAX_PAGE),
                    "displayOptions": {"showCollectionMetadata": True},
                },
            ),
            policy=self._policy,
            breaker=self._breaker,
            description=f"getAssetsByOwner({short_address(wallet)})",
        )
        items = result.get("items")
        return items if isinstance(items, list) else []

    # -- port ---------------------------------------------------------

    @staticmethod
    def _to_nft(item: dict[str, Any]) -> OwnedNFT | None:
        """Map one DAS asset, defensively.

        The provider's shape is not ours to guarantee, so anything unexpected
        is skipped rather than raised: one odd asset in a wallet must not stop
        a player from using the other forty.
        """
        mint = item.get("id")
        if not isinstance(mint, str):
            return None
        content = item.get("content") or {}
        metadata = content.get("metadata") or {}
        links = content.get("links") or {}
        grouping = item.get("grouping") or []
        collection = None
        for group in grouping:
            if isinstance(group, dict) and group.get("group_key") == "collection":
                value = group.get("group_value")
                if isinstance(value, str):
                    collection = value
                break
        return OwnedNFT(
            mint=mint,
            name=str(metadata.get("name") or mint[:8]),
            collection=collection,
            image_url=links.get("image") if isinstance(links.get("image"), str) else None,
        )

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        """Whether `wallet` holds `mint` right now.

        Returns `unavailable` rather than `not_owned` on any infrastructure
        failure. Conflating the two would deny players during an outage.
        """
        try:
            validate_mint_address(wallet, field="wallet")
            validate_mint_address(mint, field="mint")
        except ValidationError as exc:
            return OwnershipResult.not_owned(str(exc))

        if not self.configured:
            return OwnershipResult.unavailable("no RPC endpoint configured")

        try:
            for nft in self.list_owned(wallet, limit=self.MAX_PAGE):
                if nft.mint == mint:
                    return OwnershipResult.owned()
        except TransientError as exc:
            logger.warning("ownership check unavailable for %s: %s", short_address(wallet), exc)
            return OwnershipResult.unavailable(str(exc))
        except PermanentError as exc:
            logger.error("ownership check rejected for %s: %s", short_address(wallet), exc)
            return OwnershipResult.unavailable(str(exc))
        return OwnershipResult.not_owned()

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        """The NFTs `wallet` holds.

        Raises:
            TransientError / PermanentError: the caller decides what a failure
                means. `verify_ownership` turns them into an `OwnershipResult`.
        """
        validate_mint_address(wallet, field="wallet")
        if not self.configured:
            raise PermanentError("no RPC endpoint configured")
        if limit < 1:
            raise ValueError(f"limit must be positive, got {limit}")

        found: list[OwnedNFT] = []
        page = 1
        # Bounded: a wallet with a million assets must not be able to keep this
        # loop, and the player, waiting indefinitely.
        while len(found) < limit and page <= 10:
            items = self._fetch_page(wallet, page, limit - len(found))
            if not items:
                break
            for item in items:
                nft = self._to_nft(item)
                if nft is not None:
                    found.append(nft)
                if len(found) >= limit:
                    break
            page += 1
        return tuple(found)


# --------------------------------------------------------------------------
# Infrastructure adapters
# --------------------------------------------------------------------------


@CLOCKS.register("system")
class SystemClock:
    name = "system"

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


@CLOCKS.register("fixed")
class FixedClock:
    """A clock that does not move. Lets daily rotations be tested."""

    name = "fixed"

    def __init__(self, moment: datetime | None = None) -> None:
        self._moment = moment or datetime(2026, 1, 1, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self._moment

    def advance(self, seconds: float) -> None:
        from datetime import timedelta  # noqa: PLC0415

        self._moment = self._moment + timedelta(seconds=seconds)


@PLAYER_STORES.register("memory")
class MemoryPlayerStore:
    """An in-process player store.

    The default, so the game runs with no database at all. Everything is lost
    on restart, which is correct for a build whose persistence phase has not
    shipped -- better than silently pretending to save.
    """

    name = "memory"

    def __init__(self) -> None:
        self._players: dict[str, PlayerRecord] = {}

    def get_player(self, player_id: str) -> PlayerRecord | None:
        from ..store.records import validate_player_id  # noqa: PLC0415

        return self._players.get(validate_player_id(player_id))

    def upsert_player(self, record: PlayerRecord) -> PlayerRecord:
        # The same validation the Postgres store applies. Two implementations
        # of one port that enforce different rules is worse than one, because
        # the difference only shows up in production.
        from ..store.records import clean_player_record  # noqa: PLC0415

        clean = clean_player_record(record)
        self._players[clean.player_id] = clean
        return clean

    def record_result(self, player_id: str, *, won: bool, points_delta: int) -> PlayerRecord:
        from ..security.validation import ValidationError, validate_int  # noqa: PLC0415
        from ..store.records import MAX_POINTS_DELTA, validate_player_id  # noqa: PLC0415

        checked_id = validate_player_id(player_id)
        delta = validate_int(
            points_delta, field="points_delta",
            minimum=-MAX_POINTS_DELTA, maximum=MAX_POINTS_DELTA,
        )
        if not isinstance(won, bool):
            raise ValidationError("won", f"expected a boolean, got {type(won).__name__}")

        current = self._players.get(checked_id)
        if current is None:
            raise KeyError(f"unknown player {checked_id!r}")
        updated = PlayerRecord(
            player_id=current.player_id,
            display_name=current.display_name,
            wallet=current.wallet,
            points=max(0, current.points + delta),
            wins=current.wins + (1 if won else 0),
            losses=current.losses + (0 if won else 1),
            created_at=current.created_at,
            metadata=current.metadata,
        )
        self._players[checked_id] = updated
        return updated

    def leaderboard(self, *, limit: int = 50) -> Sequence[PlayerRecord]:
        from ..security.validation import ValidationError  # noqa: PLC0415

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit", f"expected an integer, got {type(limit).__name__}")
        return tuple(
            sorted(self._players.values(), key=lambda p: (-p.points, p.display_name))
        )[: max(1, min(limit, 500))]


@NOTIFIERS.register("null")
class NullNotifier:
    """Drops every message. The default until a channel is configured."""

    name = "null"

    def notify(self, player_id: str, message: str) -> bool:
        logger.debug("notification suppressed for %s", player_id)
        return False


# --------------------------------------------------------------------------
# Failover
# --------------------------------------------------------------------------


@WALLET_PROVIDERS.register("failover")
class FailoverWalletProvider:
    """Tries several providers in order until one gives a real answer.

    The distinction that makes this work is the three-state `OwnershipResult`.
    A provider that answers `not_owned` has *checked* and said no -- that is a
    real answer and the chain stops there. Only `checked=False` (an outage, a
    timeout, an open breaker, a missing key) falls through to the next.

    Without that distinction, a failover chain is dangerous rather than
    resilient: a provider that is merely down would be read as "this wallet
    holds nothing", and the chain would keep asking until some provider
    happened to say yes -- which is an ownership check that can be defeated by
    making one provider fail.

    Configure with ``RIVALFORGE_WALLET_PROVIDER=failover`` and
    ``RIVALFORGE_WALLET_FAILOVER=helius,other`` (a comma-separated list of
    registered provider names, tried left to right).
    """

    name = "failover"

    #: Never chain more than this; a long chain multiplies the worst-case
    #: latency a waiting player sees.
    MAX_PROVIDERS: Final = 4

    def __init__(
        self,
        providers: Sequence[Any] | None = None,
        *,
        env: dict[str, str] | None = None,
    ) -> None:
        if providers is None:
            providers = self._from_env(env if env is not None else dict(os.environ))
        self._providers = tuple(providers)[: self.MAX_PROVIDERS]
        if not self._providers:
            # An empty chain that silently answered "unavailable" would look
            # like an outage forever. Fail at construction instead.
            raise ValueError("a failover chain needs at least one provider")

    @staticmethod
    def _from_env(env: dict[str, str]) -> list[Any]:
        names = [n.strip() for n in env.get("RIVALFORGE_WALLET_FAILOVER", "").split(",")]
        chain: list[Any] = []
        for provider_name in [n for n in names if n]:
            if provider_name == "failover":
                continue  # a chain of chains is a configuration mistake
            chain.append(WALLET_PROVIDERS.get(provider_name)())
        return chain or [NullWalletProvider()]

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        last = OwnershipResult.unavailable("no provider in the chain answered")
        for provider in self._providers:
            try:
                result = provider.verify_ownership(wallet, mint)
            except Exception:
                # A provider that raises rather than returning is still just an
                # unavailable provider as far as the chain is concerned.
                logger.warning(
                    "wallet provider %r raised; falling through",
                    getattr(provider, "name", provider), exc_info=True,
                )
                last = OwnershipResult.unavailable("a provider failed unexpectedly")
                continue
            if result.checked:
                return result  # a real answer, yes or no
            last = result
        return last

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        for provider in self._providers:
            try:
                owned = provider.list_owned(wallet, limit=limit)
            except Exception:
                logger.warning(
                    "wallet provider %r raised while listing; falling through",
                    getattr(provider, "name", provider), exc_info=True,
                )
                continue
            if owned:
                return owned
        return ()


#: Backwards-compatible alias. The provider is not Helius-specific -- it speaks
#: the Metaplex DAS read API, which Helius is one implementation of.
WALLET_PROVIDERS.register("helius", DasWalletProvider)
HeliusWalletProvider = DasWalletProvider
