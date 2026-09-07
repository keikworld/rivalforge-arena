"""The simulation, run small, as a regression gate.

`tools/simulate.py` exists to answer "what breaks when a few hundred people use
this at once". Running a miniature version of it in CI turns that answer into a
gate: if a change makes a fight unfinishable, leaks one player's wallet into
another's chat, or lets a forged button move a match, this fails.

It is deliberately small here -- a full campaign takes minutes and belongs in a
terminal, not in every pull request.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

simulate = pytest.importorskip("simulate")
sandbox_module = pytest.importorskip("sandbox")


@pytest.fixture(scope="module")
def content():
    from rivalforge.content.loader import load_content

    return load_content()


def _config(**overrides):
    base = dict(
        seed=4242,
        players=8,
        nfts=4,
        soak_steps=120,
        threads=3,
        outage_rate=0.1,
        require_ownership=True,
        opponent="adaptive",
        max_users=500,
        phases=(
            "lifecycle", "interrupted", "abuse", "outage",
            "simultaneous", "concurrency", "soak",
        ),
    )
    base.update(overrides)
    return simulate.RunConfig(**base)


class TestTheSandboxIsSelfContained:
    def test_it_is_not_importable_from_the_installed_package(self):
        """A fake that a deployment can select is a fake that will be selected."""
        import rivalforge

        package_root = Path(rivalforge.__file__).resolve().parent
        assert not (package_root / "sandbox.py").exists()
        assert not (package_root / "simulate.py").exists()

    def test_wallets_are_real_keypairs(self):
        """A fake signature would exercise a fake verifier."""
        wallet = sandbox_module.make_wallets(1)[0]
        signature = wallet.sign("hello")
        assert signature != wallet.garbage_signature()
        assert len(signature) > 40

    def test_the_chain_can_fail_as_well_as_answer(self):
        chain = sandbox_module.SandboxChain(hard_down=True)
        result = chain.verify_ownership("W" * 32, "M" * 32)
        # Unavailable, never "not owned" -- that distinction is the whole point.
        assert result.checked is False
        assert result.verified is False


class TestASmallCampaign:
    def test_every_phase_runs_without_breaking_an_invariant(self, content):
        report = simulate.run_once(_config(), content)
        assert report["violations"] == [], report["violations"]

    def test_fights_start_finish_and_the_ledger_adds_up(self, content):
        report = simulate.run_once(_config(), content)
        fights = report["fights"]
        assert fights["started"] > 0
        assert fights["finished"] > 0
        assert (
            fights["finished"] + fights["abandoned"]
            + fights["unfinished when the run ended"]
            == fights["started"]
        )

    def test_fights_run_concurrently(self, content):
        report = simulate.run_once(_config(phases=("simultaneous",)), content)
        assert report["fights"]["peak simultaneous (sampled)"] > 1

    def test_it_works_with_ownership_enforcement_off(self, content):
        """The default deployment. Not assumed equivalent -- simulated."""
        report = simulate.run_once(_config(require_ownership=False), content)
        assert report["violations"] == [], report["violations"]

    def test_it_works_against_a_chain_that_is_mostly_down(self, content):
        report = simulate.run_once(_config(outage_rate=0.6), content)
        assert report["violations"] == [], report["violations"]
        assert report["outcomes"].get("roster unavailable (outage, not a denial)", 0) > 0

    def test_it_works_with_a_tiny_conversation_store(self, content):
        """Eviction under pressure must not corrupt anyone's session."""
        report = simulate.run_once(_config(max_users=5), content)
        assert report["violations"] == [], report["violations"]

    def test_it_works_for_players_with_no_nfts(self, content):
        report = simulate.run_once(_config(nfts=0), content)
        assert report["violations"] == [], report["violations"]
        assert report["fights"]["started"] > 0

    @pytest.mark.parametrize("opponent", ["adaptive", "aggressive", "defensive", "random"])
    def test_every_opponent_agent_can_be_played_against(self, content, opponent):
        report = simulate.run_once(
            _config(opponent=opponent, phases=("simultaneous",)), content
        )
        assert report["violations"] == [], report["violations"]
        assert report["fights"]["finished"] > 0


class TestTheGuardActuallyGuards:
    """A harness that cannot fail is a harness that proves nothing."""

    def test_it_catches_an_unbalanced_fence(self, content):
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        sandbox.api.send_message(7, "```\nunterminated")
        sim.guard.check("test", "planted")
        assert any("fenced" in v.invariant for v in sim.guard.violations)

    def test_it_catches_a_leaked_token(self, content):
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        sim.guard.watch_secret("a-session-token")
        sandbox.api.send_message(7, "your token is a-session-token")
        sim.guard.check("test", "planted")
        assert any("session token" in v.invariant for v in sim.guard.violations)

    def test_it_catches_a_wallet_in_the_wrong_chat(self, content):
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        address = sandbox_module.make_wallets(1)[0].address
        sim.guard.watch_wallet(address, chat_id=1)
        sandbox.api.send_message(2, f"wallet {address}")
        sim.guard.check("test", "planted")
        assert any("owner's chat" in v.invariant for v in sim.guard.violations)

    def test_a_wallet_in_its_own_chat_is_fine(self, content):
        """The challenge a player signs contains their address, by design."""
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        address = sandbox_module.make_wallets(1)[0].address
        sim.guard.watch_wallet(address, chat_id=1)
        sandbox.api.send_message(1, f"sign this as {address}")
        sim.guard.check("test", "planted")
        assert sim.guard.violations == []

    def test_it_catches_an_oversized_callback(self, content):
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        sandbox.api.send_message(
            7, "hi", keyboard=[[{"text": "x", "callback_data": "y" * 90}]]
        )
        sim.guard.check("test", "planted")
        assert any("callback_data" in v.invariant for v in sim.guard.violations)

    def test_it_catches_a_button_signed_for_someone_else(self, content):
        sandbox = sandbox_module.build_sandbox(content=content)
        sim = simulate.Simulation(sandbox)
        stolen = sandbox.sign("st", "strike", 999)
        sandbox.api.send_message(7, "hi", keyboard=[[{"text": "x", "callback_data": stolen}]])
        sim.guard.check("test", "planted")
        assert any("verifies for the chat" in v.invariant for v in sim.guard.violations)
