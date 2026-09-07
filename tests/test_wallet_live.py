"""Live network test of the wallet layer.

Marked `integration` and skipped by default: a unit suite that needs the
internet is a suite that fails on a train. Run it deliberately::

    pytest -m integration

It exists because the mocked tests can only prove the code does what I *think*
the provider returns. This one proved otherwise: the public Solana RPC serves
the DAS read API with no credential, so the API key this layer was originally
built to require turned out to be optional.
"""

from __future__ import annotations

import pytest

from rivalforge.content.loader import load_content
from rivalforge.engine.fighter import derive_fighter
from rivalforge.plugins.adapters import DasWalletProvider
from rivalforge.plugins.resilience import RetryPolicy

pytestmark = pytest.mark.integration

#: An active mainnet wallet holding many assets.
LIVE_WALLET = "GUfCR9mK6azb9vcpsxgXyj7XRPAKJd4KMHTTVvtncGgp"
WSOL = "So11111111111111111111111111111111111111112"


@pytest.fixture(scope="module")
def provider():
    return DasWalletProvider(
        timeout=20.0, policy=RetryPolicy(attempts=2, base_delay=0.5, total_timeout=45.0)
    )


def test_lists_real_holdings_without_a_key(provider):
    assert provider.has_key is False
    owned = provider.list_owned(LIVE_WALLET, limit=5)
    assert owned, "the live wallet should hold assets"
    for nft in owned:
        assert len(nft.mint) >= 32
        assert nft.name


def test_verifies_a_real_holding(provider):
    owned = provider.list_owned(LIVE_WALLET, limit=1)
    result = provider.verify_ownership(LIVE_WALLET, owned[0].mint)
    assert result.verified is True and result.checked is True


def test_denies_an_asset_the_wallet_does_not_hold(provider):
    result = provider.verify_ownership(LIVE_WALLET, WSOL)
    assert result.verified is False
    assert result.checked is True, "a real answer, not an outage"


def test_real_nfts_become_varied_fighters(provider):
    """The product thesis, end to end: any NFT, any collection, playable."""
    content = load_content()
    owned = provider.list_owned(LIVE_WALLET, limit=8)
    fighters = [derive_fighter(n.mint, content, name=n.name) for n in owned]
    assert len({f.supremacy.id for f in fighters}) > 1, "archetypes should vary"
    assert len({f.element for f in fighters}) > 1, "elements should vary"


def test_an_unreachable_endpoint_fails_fast_rather_than_hanging():
    provider = DasWalletProvider(
        endpoint="https://10.255.255.1", timeout=2.0,
        policy=RetryPolicy(attempts=1, base_delay=0, total_timeout=8.0),
    )
    import time  # noqa: PLC0415

    started = time.monotonic()
    result = provider.verify_ownership(LIVE_WALLET, WSOL)
    elapsed = time.monotonic() - started
    assert result.checked is False, "an outage must not read as a denial"
    assert elapsed < 12, f"took {elapsed:.1f}s -- the timeout did not hold"
