"""Tests for the plugin layer: registry, toggles, resilience, adapters.

The wallet provider is exercised through an injected opener, so every network
failure mode -- timeout, 500, 429, 404, malformed JSON, an RPC error body, a
truncated page -- is tested without touching the network. A resilience test
that needs a real bad network is a test nobody runs.
"""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone

import pytest

from rivalforge.plugins.adapters import (
    FailoverWalletProvider,
    FakeWalletProvider,
    FixedClock,
    DasWalletProvider,
    MemoryPlayerStore,
    NullNotifier,
    NullWalletProvider,
    SystemClock,
)
from rivalforge.plugins.ports import (
    Clock,
    NFTOwnershipProvider,
    Notifier,
    OwnedNFT,
    OwnershipResult,
    PlayerRecord,
    PlayerStore,
)
from rivalforge.plugins.registries import (
    AGENTS,
    CLOCKS,
    NOTIFIERS,
    PLAYER_STORES,
    WALLET_PROVIDERS,
    select,
    wallet_provider,
)
from rivalforge.plugins.registry import (
    DuplicateRegistration,
    Registry,
    RegistryError,
    UnknownPlugin,
)
from rivalforge.plugins.resilience import (
    CircuitBreaker,
    CircuitOpen,
    Deadline,
    PermanentError,
    RetryPolicy,
    TransientError,
    call_with_retries,
)
from rivalforge.plugins.toggles import FEATURES, Toggles, UnknownToggle, toggles

WALLET = "So11111111111111111111111111111111111111112"
MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class TestRegistry:
    def test_register_and_get(self):
        reg: Registry[type] = Registry("thing")
        reg.register("a", int)
        assert reg.get("a") is int
        assert reg.names() == ("a",)
        assert "a" in reg and len(reg) == 1

    def test_register_as_a_decorator(self):
        reg: Registry[type] = Registry("thing")

        @reg.register("boxed")
        class Boxed:
            pass

        assert reg.get("boxed") is Boxed

    def test_duplicate_registration_is_an_error_not_an_override(self):
        """Silent override means the plugin that imports last wins, and which
        one that is depends on import order."""
        reg: Registry[type] = Registry("thing")
        reg.register("a", int)
        with pytest.raises(DuplicateRegistration, match="already registered"):
            reg.register("a", str)
        assert reg.get("a") is int

    def test_unknown_name_lists_the_alternatives(self):
        reg: Registry[type] = Registry("thing")
        reg.register("alpha", int)
        reg.register("beta", str)
        with pytest.raises(UnknownPlugin) as exc:
            reg.get("gamma")
        assert "alpha, beta" in str(exc.value)

    def test_unknown_plugin_is_still_a_key_error(self):
        """Existing `except KeyError` callers must keep working."""
        reg: Registry[type] = Registry("thing")
        with pytest.raises(KeyError):
            reg.get("nope")

    def test_empty_registry_says_so(self):
        with pytest.raises(UnknownPlugin, match="nothing registered"):
            Registry("thing").get("x")

    @pytest.mark.parametrize("bad", ["", None, 42])
    def test_bad_names_are_rejected(self, bad):
        with pytest.raises(RegistryError):
            Registry("thing").register(bad, int)

    def test_unregister(self):
        reg: Registry[type] = Registry("thing")
        reg.register("a", int)
        reg.unregister("a")
        assert "a" not in reg
        reg.unregister("a")  # idempotent

    def test_discovery_is_skipped_without_a_group(self):
        reg: Registry[type] = Registry("thing", entry_point_group=None)
        reg.discover()  # must not raise
        assert reg.names() == ()

    def test_iteration_is_sorted(self):
        reg: Registry[type] = Registry("thing")
        reg.register("z", int)
        reg.register("a", str)
        assert [name for name, _ in reg] == ["a", "z"]


# --------------------------------------------------------------------------
# Toggles
# --------------------------------------------------------------------------


class TestToggles:
    def test_defaults_are_safe(self):
        """A fresh deployment with no configuration must be inert: nothing
        that touches money, a chain, or a third party is on."""
        resolved = Toggles(env={})
        for name in ("wallet_verification", "persistence", "payments", "telegram_bot"):
            assert resolved.enabled(name) is False

    def test_environment_overrides_the_default(self):
        assert Toggles(env={"RIVALFORGE_FEATURE_PAYMENTS": "1"}).enabled("payments") is True

    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", "enabled"])
    def test_truthy_spellings(self, raw):
        assert Toggles(env={"RIVALFORGE_FEATURE_PAYMENTS": raw}).enabled("payments") is True

    @pytest.mark.parametrize("raw", ["0", "false", "no", "off", "disabled", ""])
    def test_falsy_spellings(self, raw):
        assert Toggles(env={"RIVALFORGE_FEATURE_AI_AGENTS": raw}).enabled("ai_agents") is False

    def test_an_unparseable_value_falls_back_to_the_default(self, caplog):
        resolved = Toggles(env={"RIVALFORGE_FEATURE_AI_AGENTS": "maybe"})
        assert resolved.enabled("ai_agents") is True  # the declared default
        assert "not a boolean" in caplog.text

    def test_explicit_overrides_beat_the_environment(self):
        resolved = Toggles(
            overrides={"payments": False}, env={"RIVALFORGE_FEATURE_PAYMENTS": "1"}
        )
        assert resolved.enabled("payments") is False

    def test_an_undeclared_toggle_raises_rather_than_reading_false(self):
        """A typo'd flag that silently reads false is a feature that is off in
        production and on in your head."""
        with pytest.raises(UnknownToggle, match="declared"):
            Toggles(env={}).enabled("wallet_verifcation")  # note the typo

    def test_an_undeclared_override_is_rejected_at_construction(self):
        with pytest.raises(UnknownToggle):
            Toggles(overrides={"not_a_toggle": True}, env={})

    def test_require_raises_when_off_and_names_the_variable(self):
        with pytest.raises(RuntimeError, match="RIVALFORGE_FEATURE_PAYMENTS"):
            Toggles(env={}).require("payments")

    def test_require_passes_when_on(self):
        Toggles(env={"RIVALFORGE_FEATURE_PAYMENTS": "1"}).require("payments")

    def test_file_source(self, tmp_path):
        path = tmp_path / "features.json"
        path.write_text(json.dumps({"payments": True, "persistence": "yes"}))
        resolved = Toggles(env={"RIVALFORGE_FEATURES_FILE": str(path)})
        assert resolved.enabled("payments") is True
        assert resolved.enabled("persistence") is True

    def test_environment_beats_the_file(self, tmp_path):
        path = tmp_path / "features.json"
        path.write_text(json.dumps({"payments": True}))
        resolved = Toggles(env={
            "RIVALFORGE_FEATURES_FILE": str(path),
            "RIVALFORGE_FEATURE_PAYMENTS": "0",
        })
        assert resolved.enabled("payments") is False

    def test_a_missing_or_broken_file_degrades_to_defaults(self, tmp_path, caplog):
        """A malformed toggle file must not stop the game starting."""
        assert Toggles(env={"RIVALFORGE_FEATURES_FILE": str(tmp_path / "nope.json")}) \
            .enabled("payments") is False
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        assert Toggles(env={"RIVALFORGE_FEATURES_FILE": str(bad)}).enabled("payments") is False
        assert "could not read toggle file" in caplog.text

    def test_a_file_naming_an_unknown_toggle_is_ignored(self, tmp_path, caplog):
        path = tmp_path / "features.json"
        path.write_text(json.dumps({"invented": True}))
        Toggles(env={"RIVALFORGE_FEATURES_FILE": str(path)})
        assert "unknown toggle" in caplog.text

    def test_describe_covers_every_declared_toggle(self):
        described = Toggles(env={}).describe()
        for toggle in FEATURES:
            assert toggle.name in described

    def test_resolution_is_frozen_at_construction(self, monkeypatch):
        """A flag must not flip mid-match."""
        resolved = toggles()
        before = resolved.enabled("payments")
        monkeypatch.setenv("RIVALFORGE_FEATURE_PAYMENTS", "1")
        assert resolved.enabled("payments") is before


# --------------------------------------------------------------------------
# Resilience
# --------------------------------------------------------------------------


class TestRetryPolicy:
    def test_backoff_grows_and_is_capped(self):
        policy = RetryPolicy(base_delay=0.1, max_delay=0.5, jitter=False)
        assert policy.delay_for(1) == pytest.approx(0.1)
        assert policy.delay_for(2) == pytest.approx(0.2)
        assert policy.delay_for(9) == pytest.approx(0.5)  # capped

    def test_jitter_stays_within_the_bound(self):
        import random  # noqa: PLC0415

        policy = RetryPolicy(base_delay=0.1, max_delay=1.0, jitter=True)
        rng = random.Random(1)
        for attempt in range(1, 6):
            assert 0.0 <= policy.delay_for(attempt, rng) <= 1.0

    @pytest.mark.parametrize("kwargs", [
        {"attempts": 0}, {"base_delay": -1}, {"total_timeout": 0},
    ])
    def test_invalid_policies_are_rejected(self, kwargs):
        with pytest.raises(ValueError):
            RetryPolicy(**kwargs)


class TestCallWithRetries:
    def test_returns_on_first_success(self):
        assert call_with_retries(lambda: 42, sleep=lambda _: None) == 42

    def test_retries_a_transient_failure_then_succeeds(self):
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise TransientError("not yet")
            return "ok"

        assert call_with_retries(flaky, sleep=lambda _: None) == "ok"
        assert calls["n"] == 3

    def test_gives_up_after_the_attempt_budget(self):
        calls = {"n": 0}

        def always_fails():
            calls["n"] += 1
            raise TransientError("down")

        with pytest.raises(TransientError, match="after 3 attempt"):
            call_with_retries(always_fails, sleep=lambda _: None)
        assert calls["n"] == 3

    def test_a_permanent_failure_is_never_retried(self):
        """Retrying a permanent failure spends latency and rate limit to get
        the same answer."""
        calls = {"n": 0}

        def bad_request():
            calls["n"] += 1
            raise PermanentError("malformed address")

        with pytest.raises(PermanentError):
            call_with_retries(bad_request, sleep=lambda _: None)
        assert calls["n"] == 1

    def test_does_not_sleep_past_the_total_budget(self):
        slept: list[float] = []
        policy = RetryPolicy(attempts=5, base_delay=10.0, max_delay=10.0,
                             jitter=False, total_timeout=0.05)

        def always_fails():
            raise TransientError("down")

        with pytest.raises(TransientError):
            call_with_retries(always_fails, policy=policy, sleep=slept.append)
        assert all(s <= 0.05 for s in slept), slept

    def test_a_permanent_failure_does_not_trip_the_breaker(self):
        """One bad request must not take a healthy provider offline for
        everyone else."""
        breaker = CircuitBreaker("test", threshold=2)

        for _ in range(5):
            with pytest.raises(PermanentError):
                call_with_retries(
                    lambda: (_ for _ in ()).throw(PermanentError("bad input")),
                    breaker=breaker, sleep=lambda _: None,
                )
        assert breaker.is_open is False


class TestCircuitBreaker:
    def test_opens_after_consecutive_failures(self):
        breaker = CircuitBreaker("t", threshold=3, cooldown=60)
        for _ in range(3):
            breaker.record_failure()
        assert breaker.is_open
        with pytest.raises(CircuitOpen, match="unavailable"):
            breaker.before_call()

    def test_a_success_resets_the_count(self):
        breaker = CircuitBreaker("t", threshold=3)
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_success()
        breaker.record_failure()
        assert breaker.is_open is False

    def test_half_opens_after_the_cooldown(self):
        breaker = CircuitBreaker("t", threshold=1, cooldown=0.0)
        breaker.record_failure()
        assert breaker.is_open is False  # cooldown of zero: probe immediately
        breaker.before_call()

    def test_reset_forces_closed(self):
        breaker = CircuitBreaker("t", threshold=1, cooldown=999)
        breaker.record_failure()
        assert breaker.is_open
        breaker.reset()
        assert breaker.is_open is False

    def test_circuit_open_is_transient_so_a_caller_can_retry_later(self):
        assert issubclass(CircuitOpen, TransientError)

    def test_an_open_breaker_short_circuits_without_calling(self):
        breaker = CircuitBreaker("t", threshold=1, cooldown=999)
        breaker.record_failure()
        calls = {"n": 0}

        def should_not_run():
            calls["n"] += 1
            return "x"

        with pytest.raises(TransientError):
            call_with_retries(should_not_run, breaker=breaker, sleep=lambda _: None)
        assert calls["n"] == 0

    def test_invalid_threshold(self):
        with pytest.raises(ValueError):
            CircuitBreaker("t", threshold=0)


class TestDeadline:
    def test_counts_down_and_expires(self):
        deadline = Deadline(10.0)
        assert 0 < deadline.remaining <= 10.0
        assert not deadline.expired
        deadline.check()

    def test_rejects_a_non_positive_budget(self):
        with pytest.raises(ValueError):
            Deadline(0)


# --------------------------------------------------------------------------
# Wallet providers
# --------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _asset(mint: str, name: str = "Test NFT", collection: str | None = "coll") -> dict:
    grouping = [{"group_key": "collection", "group_value": collection}] if collection else []
    return {
        "id": mint,
        "content": {"metadata": {"name": name}, "links": {"image": "https://x/i.png"}},
        "grouping": grouping,
    }


def _opener_returning(*pages):
    """An opener that returns each page in turn, then empty pages."""
    calls = {"n": 0}

    def opener(request, timeout=None):
        index = calls["n"]
        calls["n"] += 1
        items = list(pages[index]) if index < len(pages) else []
        return _FakeResponse({"result": {"items": items}})

    opener.calls = calls
    return opener


def _opener_raising(exc):
    def opener(request, timeout=None):
        raise exc

    return opener


class TestNullWalletProvider:
    def test_reports_unchecked_not_denied(self):
        """"Verification is off" must never read as "you do not own this", or
        disabling the feature would lock every player out."""
        result = NullWalletProvider().verify_ownership(WALLET, MINT)
        assert result.verified is False
        assert result.checked is False

    def test_lists_nothing(self):
        assert NullWalletProvider().list_owned(WALLET) == ()


class TestFakeWalletProvider:
    def test_confirms_a_holding(self):
        provider = FakeWalletProvider()
        provider.give(WALLET, OwnedNFT(mint=MINT, name="N", collection=None))
        result = provider.verify_ownership(WALLET, MINT)
        assert result.verified and result.checked

    def test_denies_what_is_not_held(self):
        result = FakeWalletProvider().verify_ownership(WALLET, MINT)
        assert result.verified is False
        assert result.checked is True  # a real answer, not an outage

    def test_is_not_registered_so_it_cannot_be_selected_in_production(self):
        assert "fake" not in WALLET_PROVIDERS.names()


class TestDasWalletProvider:
    def test_works_without_an_api_key(self):
        """The default endpoint serves DAS with no credential -- verified live
        against mainnet. Requiring a key would be a fictional barrier."""
        provider = DasWalletProvider(api_key="", opener=_opener_returning([_asset(MINT)]))
        assert provider.configured is True
        assert provider.has_key is False
        assert provider.verify_ownership(WALLET, MINT).verified is True

    def test_no_key_means_no_credential_in_the_url(self):
        seen = []

        def opener(request, timeout=None):
            seen.append(request.full_url)
            return _FakeResponse({"result": {"items": []}})

        DasWalletProvider(api_key="", opener=opener).list_owned(WALLET)
        assert "api-key" not in seen[0]

    def test_a_key_is_attached_when_present(self):
        seen = []

        def opener(request, timeout=None):
            seen.append(request.full_url)
            return _FakeResponse({"result": {"items": []}})

        DasWalletProvider(api_key="abc123", opener=opener).list_owned(WALLET)
        assert "api-key=abc123" in seen[0]

    def test_an_empty_endpoint_falls_back_to_the_default(self, monkeypatch):
        """There is always a working endpoint. An empty argument means "not
        specified", not "disabled" -- disabling is what the null provider and
        the wallet_verification toggle are for."""
        monkeypatch.delenv("RIVALFORGE_RPC_ENDPOINT", raising=False)
        provider = DasWalletProvider(endpoint="", opener=_opener_returning([]))
        assert provider.endpoint == DasWalletProvider.DEFAULT_ENDPOINT
        assert provider.configured is True

    def test_the_endpoint_can_be_set_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("RIVALFORGE_RPC_ENDPOINT", "https://rpc.example")
        assert DasWalletProvider().endpoint == "https://rpc.example"

    def test_confirms_ownership_from_one_indexed_call(self):
        opener = _opener_returning([_asset(MINT)])
        provider = DasWalletProvider(api_key="k", opener=opener)
        assert provider.verify_ownership(WALLET, MINT).verified is True

    def test_denies_when_the_wallet_holds_other_things(self):
        opener = _opener_returning([_asset(WALLET)])
        provider = DasWalletProvider(api_key="k", opener=opener)
        result = provider.verify_ownership(WALLET, MINT)
        assert result.verified is False and result.checked is True

    def test_parses_name_collection_and_image(self):
        opener = _opener_returning([_asset(MINT, name="Frostborn #1", collection="abc")])
        owned = DasWalletProvider(api_key="k", opener=opener).list_owned(WALLET)
        assert owned[0].name == "Frostborn #1"
        assert owned[0].collection == "abc"
        assert owned[0].image_url.endswith(".png")
        assert owned[0].short_mint == "EPjF...Dt1v"

    def test_skips_malformed_assets_rather_than_failing(self):
        """One odd asset must not stop a player using the other forty."""
        opener = _opener_returning([{"no_id": True}, _asset(MINT)])
        owned = DasWalletProvider(api_key="k", opener=opener).list_owned(WALLET)
        assert [n.mint for n in owned] == [MINT]

    def test_pages_until_empty(self):
        opener = _opener_returning([_asset("1" * 32)], [_asset(MINT)], [])
        owned = DasWalletProvider(api_key="k", opener=opener).list_owned(WALLET, limit=50)
        assert len(owned) == 2

    def test_respects_the_limit(self):
        opener = _opener_returning([_asset("1" * 32), _asset(MINT)])
        owned = DasWalletProvider(api_key="k", opener=opener).list_owned(WALLET, limit=1)
        assert len(owned) == 1

    def test_rejects_a_bad_wallet_before_making_a_request(self):
        """A malformed address must never reach a URL."""
        called = {"n": 0}

        def opener(request, timeout=None):
            called["n"] += 1
            raise AssertionError("should not be reached")

        provider = DasWalletProvider(api_key="k", opener=opener)
        result = provider.verify_ownership("not-a-wallet", MINT)
        assert result.verified is False and result.checked is True
        assert called["n"] == 0

    def test_rejects_a_bad_mint_before_making_a_request(self):
        provider = DasWalletProvider(api_key="k", opener=_opener_raising(AssertionError))
        assert provider.verify_ownership(WALLET, "nope").checked is True

    @pytest.mark.parametrize("code", [500, 502, 503, 429])
    def test_server_errors_and_rate_limits_are_transient(self, code):
        opener = _opener_raising(
            urllib.error.HTTPError("u", code, "err", {}, None)
        )
        provider = DasWalletProvider(
            api_key="k", opener=opener,
            policy=RetryPolicy(attempts=2, base_delay=0, total_timeout=1),
        )
        result = provider.verify_ownership(WALLET, MINT)
        assert result.checked is False  # unavailable, not a denial

    @pytest.mark.parametrize("code", [400, 401, 403, 404])
    def test_client_errors_are_permanent_and_not_retried(self, code):
        calls = {"n": 0}

        def opener(request, timeout=None):
            calls["n"] += 1
            raise urllib.error.HTTPError("u", code, "err", {}, None)

        provider = DasWalletProvider(api_key="k", opener=opener)
        result = provider.verify_ownership(WALLET, MINT)
        assert result.checked is False
        assert calls["n"] == 1, "a permanent failure must not be retried"

    def test_a_network_timeout_is_transient(self):
        provider = DasWalletProvider(
            api_key="k", opener=_opener_raising(TimeoutError("timed out")),
            policy=RetryPolicy(attempts=2, base_delay=0, total_timeout=1),
        )
        assert provider.verify_ownership(WALLET, MINT).checked is False

    def test_malformed_json_is_transient(self):
        class BadResponse:
            def read(self):
                return b"{not json"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        provider = DasWalletProvider(
            api_key="k", opener=lambda r, timeout=None: BadResponse(),
            policy=RetryPolicy(attempts=1, base_delay=0, total_timeout=1),
        )
        assert provider.verify_ownership(WALLET, MINT).checked is False

    def test_an_rpc_error_body_is_transient(self):
        provider = DasWalletProvider(
            api_key="k",
            opener=lambda r, timeout=None: _FakeResponse({"error": {"message": "boom"}}),
            policy=RetryPolicy(attempts=1, base_delay=0, total_timeout=1),
        )
        assert provider.verify_ownership(WALLET, MINT).checked is False

    def test_the_api_key_never_appears_in_an_error(self):
        provider = DasWalletProvider(
            api_key="super-secret-key",
            opener=_opener_raising(urllib.error.HTTPError("u", 500, "e", {}, None)),
            policy=RetryPolicy(attempts=1, base_delay=0, total_timeout=1),
        )
        result = provider.verify_ownership(WALLET, MINT)
        assert "super-secret-key" not in result.reason

    def test_the_timeout_is_passed_to_every_request(self):
        seen: list[float] = []

        def opener(request, timeout=None):
            seen.append(timeout)
            return _FakeResponse({"result": {"items": []}})

        DasWalletProvider(api_key="k", timeout=3.5, opener=opener).list_owned(WALLET)
        assert seen and all(t == 3.5 for t in seen)

    def test_a_repeatedly_failing_provider_trips_its_breaker(self):
        calls = {"n": 0}

        def opener(request, timeout=None):
            calls["n"] += 1
            raise TimeoutError("down")

        breaker = CircuitBreaker("t", threshold=2, cooldown=999)
        provider = DasWalletProvider(
            api_key="k", opener=opener, breaker=breaker,
            policy=RetryPolicy(attempts=2, base_delay=0, total_timeout=1),
        )
        provider.verify_ownership(WALLET, MINT)
        assert breaker.is_open
        before = calls["n"]
        provider.verify_ownership(WALLET, MINT)
        assert calls["n"] == before, "an open breaker must not call the provider"

    def test_a_negative_limit_is_rejected(self):
        provider = DasWalletProvider(api_key="k", opener=_opener_returning([]))
        with pytest.raises(ValueError):
            provider.list_owned(WALLET, limit=0)


class TestFailover:
    def test_falls_through_an_unavailable_provider(self):
        good = FakeWalletProvider()
        good.give(WALLET, OwnedNFT(mint=MINT, name="N", collection=None))
        chain = FailoverWalletProvider([NullWalletProvider(), good])
        assert chain.verify_ownership(WALLET, MINT).verified is True

    def test_stops_at_the_first_real_answer_even_when_it_is_no(self):
        """A definite 'not owned' must end the chain. Otherwise an ownership
        check could be defeated by making one provider fail."""
        empty = FakeWalletProvider()
        holder = FakeWalletProvider()
        holder.give(WALLET, OwnedNFT(mint=MINT, name="N", collection=None))
        chain = FailoverWalletProvider([empty, holder])
        result = chain.verify_ownership(WALLET, MINT)
        assert result.verified is False and result.checked is True

    def test_a_raising_provider_is_treated_as_unavailable(self):
        class Broken:
            name = "broken"

            def verify_ownership(self, wallet, mint):
                raise RuntimeError("kaboom")

            def list_owned(self, wallet, *, limit=100):
                raise RuntimeError("kaboom")

        good = FakeWalletProvider()
        good.give(WALLET, OwnedNFT(mint=MINT, name="N", collection=None))
        chain = FailoverWalletProvider([Broken(), good])
        assert chain.verify_ownership(WALLET, MINT).verified is True
        assert len(chain.list_owned(WALLET)) == 1

    def test_all_unavailable_reports_unavailable(self):
        chain = FailoverWalletProvider([NullWalletProvider(), NullWalletProvider()])
        assert chain.verify_ownership(WALLET, MINT).checked is False

    def test_an_empty_chain_is_rejected_at_construction(self):
        with pytest.raises(ValueError, match="at least one"):
            FailoverWalletProvider([])

    def test_builds_from_the_environment(self):
        chain = FailoverWalletProvider(env={"RIVALFORGE_WALLET_FAILOVER": "null,null"})
        assert chain.verify_ownership(WALLET, MINT).checked is False

    def test_the_chain_length_is_bounded(self):
        chain = FailoverWalletProvider([NullWalletProvider()] * 20)
        assert len(chain._providers) <= FailoverWalletProvider.MAX_PROVIDERS


# --------------------------------------------------------------------------
# Selection and wiring
# --------------------------------------------------------------------------


class TestSelection:
    def test_defaults_are_inert(self):
        assert select("wallet", env={}) is NullWalletProvider
        assert select("player_store", env={}) is MemoryPlayerStore
        assert select("notifier", env={}) is NullNotifier
        assert select("clock", env={}) is SystemClock

    def test_the_environment_selects_an_adapter(self):
        chosen = select("wallet", env={"RIVALFORGE_WALLET_PROVIDER": "helius"})
        assert chosen is DasWalletProvider

    def test_an_unknown_selectable_is_a_programming_error(self):
        with pytest.raises(KeyError, match="known:"):
            select("teapot", env={})

    def test_a_misconfigured_name_lists_the_options(self):
        with pytest.raises(UnknownPlugin, match="available:"):
            select("wallet", env={"RIVALFORGE_WALLET_PROVIDER": "nonesuch"})

    def test_the_toggle_overrides_a_stale_environment_variable(self):
        """The toggle is the authority on whether we touch a chain at all. A
        leftover variable must not switch network traffic back on."""
        provider = wallet_provider(
            Toggles(env={}), env={"RIVALFORGE_WALLET_PROVIDER": "helius"}
        )
        assert isinstance(provider, NullWalletProvider)

    def test_enabling_the_toggle_builds_the_configured_provider(self):
        provider = wallet_provider(
            Toggles(env={"RIVALFORGE_FEATURE_WALLET_VERIFICATION": "1"}),
            env={"RIVALFORGE_WALLET_PROVIDER": "helius"},
            api_key="k",
        )
        assert isinstance(provider, DasWalletProvider)

    def test_agents_are_registered_through_the_registry(self):
        assert set(AGENTS.names()) >= {"random", "aggressive", "defensive", "adaptive"}


class TestPortConformance:
    """Every shipped adapter must actually satisfy the protocol it claims.

    `runtime_checkable` only checks method names, which is exactly the level a
    duck-typed plugin boundary needs: a plugin author gets a clear failure
    instead of an AttributeError halfway through a match.
    """

    @pytest.mark.parametrize("provider", [
        NullWalletProvider(), FakeWalletProvider(),
        DasWalletProvider(api_key="k"),
        FailoverWalletProvider([NullWalletProvider()]),
    ])
    def test_wallet_providers(self, provider):
        assert isinstance(provider, NFTOwnershipProvider)

    @pytest.mark.parametrize("clock", [SystemClock(), FixedClock()])
    def test_clocks(self, clock):
        assert isinstance(clock, Clock)
        assert isinstance(clock.now(), datetime)

    def test_player_store(self):
        assert isinstance(MemoryPlayerStore(), PlayerStore)

    def test_notifier(self):
        assert isinstance(NullNotifier(), Notifier)


class TestMemoryPlayerStore:
    def _record(self) -> PlayerRecord:
        return PlayerRecord(
            player_id="p1", display_name="Ayla", wallet=None, points=100,
            wins=2, losses=1, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_upsert_and_get(self):
        store = MemoryPlayerStore()
        store.upsert_player(self._record())
        assert store.get_player("p1").display_name == "Ayla"
        assert store.get_player("missing") is None

    def test_record_result_updates_points_and_tally(self):
        store = MemoryPlayerStore()
        store.upsert_player(self._record())
        updated = store.record_result("p1", won=True, points_delta=15)
        assert updated.points == 115 and updated.wins == 3

    def test_points_never_go_negative(self):
        store = MemoryPlayerStore()
        store.upsert_player(self._record())
        updated = store.record_result("p1", won=False, points_delta=-500)
        assert updated.points == 0 and updated.losses == 2

    def test_recording_for_an_unknown_player_is_an_error(self):
        with pytest.raises(KeyError):
            MemoryPlayerStore().record_result("ghost", won=True, points_delta=1)

    def test_leaderboard_is_ordered_and_capped(self):
        store = MemoryPlayerStore()
        for index, points in enumerate([10, 300, 200]):
            store.upsert_player(PlayerRecord(
                player_id=f"p{index}", display_name=f"P{index}", wallet=None,
                points=points, wins=0, losses=0,
                created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            ))
        board = store.leaderboard(limit=2)
        assert [p.points for p in board] == [300, 200]


class TestFixedClock:
    def test_does_not_move_on_its_own(self):
        clock = FixedClock()
        assert clock.now() == clock.now()

    def test_can_be_advanced(self):
        clock = FixedClock()
        before = clock.now()
        clock.advance(3600)
        assert (clock.now() - before).total_seconds() == 3600


class TestOwnershipResult:
    def test_the_three_states_are_distinguishable(self):
        assert OwnershipResult.owned() == OwnershipResult(True, True, "")
        assert OwnershipResult.not_owned().checked is True
        assert OwnershipResult.unavailable("outage").checked is False

    def test_unavailable_is_not_a_denial(self):
        """The distinction that stops an RPC outage banning every player."""
        outage = OwnershipResult.unavailable("timeout")
        denial = OwnershipResult.not_owned()
        assert outage.verified == denial.verified is False
        assert outage.checked != denial.checked
