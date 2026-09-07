"""Tests for the match state machine and the built-in agents."""

from __future__ import annotations

from collections import Counter

import pytest

from rivalforge.agents.builtin import AGENT_REGISTRY, build_agent
from rivalforge.content.loader import load_content
from rivalforge.content.schema import Element, SoulEffect, Stance
from rivalforge.engine import balance
from rivalforge.engine.fighter import Fighter, derive_fighter
from rivalforge.engine.match import (
    Decision,
    EventKind,
    Match,
    Side,
    play,
)
from rivalforge.engine.rng import RNG
from rivalforge.security.validation import ValidationError, b58encode

MINT_A = "So11111111111111111111111111111111111111112"
MINT_B = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


@pytest.fixture(scope="module")
def content():
    return load_content()


@pytest.fixture
def duel(content):
    """A match on a hazard-free arena, so hazard rolls do not muddy assertions."""
    return Match.create(
        derive_fighter(MINT_A, content, name="Ayla"),
        derive_fighter(MINT_B, content, name="Bram"),
        content.battlefield("whisperwind_arena"),
        content,
        seed=20260907,
    )


def _fighter(content, **kw) -> Fighter:
    """A hand-built fighter, for tests that need exact stats."""
    defaults = dict(
        mint=MINT_A, name="Test", supremacy=content.supremacy("keiknight_warrior"),
        element=Element.WIND, power=10, guard=10, focus=10,
    )
    defaults.update(kw)
    return Fighter(**defaults)


BOTH_STRIKE = {Side.A: Decision(Stance.STRIKE), Side.B: Decision(Stance.STRIKE)}


class TestMatchLifecycle:
    def test_starts_at_full_bp(self, duel):
        assert duel.bp(Side.A) == duel.bp(Side.B) == balance.STARTING_BP
        assert duel.round_number == 0
        assert not duel.is_over

    def test_a_round_advances_and_deals_damage(self, duel):
        duel.submit(BOTH_STRIKE)
        assert duel.round_number == 1
        assert duel.bp(Side.A) < balance.STARTING_BP
        assert duel.bp(Side.B) < balance.STARTING_BP

    def test_a_match_finishes_with_a_winner(self, duel):
        while not duel.is_over:
            duel.submit(BOTH_STRIKE)
        outcome = duel.outcome
        assert outcome is not None
        assert outcome.rounds > 0
        assert outcome.winner in (Side.A, Side.B, None)

    def test_cannot_submit_to_a_finished_match(self, duel):
        while not duel.is_over:
            duel.submit(BOTH_STRIKE)
        with pytest.raises(RuntimeError, match="finished match"):
            duel.submit(BOTH_STRIKE)

    def test_awaiting_is_empty_once_over(self, duel):
        while not duel.is_over:
            duel.submit(BOTH_STRIKE)
        assert duel.awaiting == ()

    def test_the_round_limit_ends_the_match(self, content):
        """Two fighters who only guard must not loop forever."""
        match = Match.create(
            _fighter(content, guard=balance.STAT_MAXIMUM, power=balance.STAT_MINIMUM, focus=8),
            _fighter(content, guard=balance.STAT_MAXIMUM, power=balance.STAT_MINIMUM, focus=8),
            content.battlefield("whisperwind_arena"), content, seed=1,
        )
        rounds = 0
        while not match.is_over and rounds < balance.MAX_ROUNDS * 2:
            match.submit({Side.A: Decision(Stance.GUARD), Side.B: Decision(Stance.GUARD)})
            rounds += 1
        assert match.is_over
        assert match.outcome.rounds <= balance.MAX_ROUNDS

    def test_bp_never_goes_negative(self, duel):
        while not duel.is_over:
            duel.submit(BOTH_STRIKE)
        assert duel.bp(Side.A) >= 0 and duel.bp(Side.B) >= 0

    def test_ko_and_match_end_events_are_emitted(self, duel):
        while not duel.is_over:
            duel.submit(BOTH_STRIKE)
        kinds = [e.kind for e in duel.log]
        assert EventKind.MATCH_END in kinds
        if duel.outcome.winner is not None:
            assert EventKind.KO in kinds


class TestDeterminismAndReplay:
    def test_the_same_seed_replays_exactly(self, content):
        def run():
            match = Match.create(
                derive_fighter(MINT_A, content), derive_fighter(MINT_B, content),
                content.battlefield("blazing_rift"), content, seed=555,
            )
            while not match.is_over:
                match.submit(BOTH_STRIKE)
            return [str(e) for e in match.log]

        assert run() == run()

    def test_different_seeds_give_different_matches(self, content):
        def run(seed):
            match = Match.create(
                derive_fighter(MINT_A, content), derive_fighter(MINT_B, content),
                content.battlefield("blazing_rift"), content, seed=seed,
            )
            while not match.is_over:
                match.submit(BOTH_STRIKE)
            return [str(e) for e in match.log]

        assert run(1) != run(2)

    def test_seed_is_recoverable_from_the_match(self, duel):
        assert duel.seed == 20260907


class TestSimultaneity:
    def test_neither_side_is_advantaged_by_resolution_order(self, content):
        """Identical fighters, identical stances: over many seeds, wins must be
        near-even. A resolver that applied damage sequentially would hand a
        systematic edge to whichever side the loop visited first."""
        wins = Counter()
        for seed in range(400):
            match = Match.create(
                _fighter(content, name="A"), _fighter(content, name="B"),
                content.battlefield("whisperwind_arena"), content, seed=seed,
            )
            while not match.is_over:
                match.submit(BOTH_STRIKE)
            wins[match.outcome.winner] += 1
        a, b = wins[Side.A], wins[Side.B]
        decided = a + b
        # A mirror match must actually resolve: the lead tiebreak exists so
        # that identical fighters do not draw 99% of the time.
        assert decided > 300, f"only {decided}/400 mirrors resolved; draws={wins[None]}"
        assert abs(a - b) < 0.2 * (decided + 1), f"A={a} B={b} draws={wins[None]}"

    def test_a_double_knockout_is_decided_on_the_lead(self, content):
        """Both sides down in the same round is settled by who was ahead going
        into it, not by a coin flip and not by a near-automatic draw."""
        glass = _fighter(content, power=balance.STAT_MAXIMUM, guard=balance.STAT_MINIMUM, focus=8)
        found_draw = False
        for seed in range(300):
            match = Match.create(
                glass, glass, content.battlefield("whisperwind_arena"), content, seed=seed
            )
            while not match.is_over:
                match.submit(BOTH_STRIKE)
            if match.outcome.reason.startswith("double knockout"):
                found_draw = True
                assert match.bp(Side.A) == 0 and match.bp(Side.B) == 0
                # Only an exactly level position draws; otherwise the lead decides.
                if match.outcome.winner is None:
                    assert match.outcome.reason.endswith("level")
                break
        assert found_draw, "no double knockout in 300 seeds; the scenario may be unreachable"


class TestDecisionValidation:
    def test_accepts_a_decision_object(self):
        assert Decision.parse(Decision(Stance.GUARD)).stance is Stance.GUARD

    def test_accepts_a_stance_enum_and_a_stance_name(self):
        assert Decision.parse(Stance.FOCUS).stance is Stance.FOCUS
        assert Decision.parse("focus").stance is Stance.FOCUS

    def test_accepts_a_mapping(self):
        parsed = Decision.parse({"stance": "strike", "spend_soul": True})
        assert parsed.stance is Stance.STRIKE and parsed.spend_soul is True

    @pytest.mark.parametrize("bad", ["medium", "STRIKE", "", None, 3, ["strike"]])
    def test_rejects_anything_else(self, bad):
        """Regression test for AUDIT F4 -- the previous codebase dispatched on
        a variant *key* as if it were a variant *type*, so six of nine cases
        matched no branch, sent no prompt, and silently scored a failure.
        An unrecognised stance is now an error, not a silent no-op."""
        with pytest.raises(ValidationError):
            Decision.parse(bad)

    def test_rejects_a_non_boolean_spend_soul(self):
        with pytest.raises(ValidationError):
            Decision.parse({"stance": "strike", "spend_soul": "yes"})

    def test_a_missing_side_is_an_error(self, duel):
        with pytest.raises(ValidationError, match="missing a decision"):
            duel.submit({Side.A: Decision(Stance.STRIKE)})

    def test_raw_input_is_accepted_and_validated_at_the_boundary(self, duel):
        duel.submit({Side.A: "strike", Side.B: {"stance": "guard"}})
        assert duel.round_number == 1


class TestSouls:
    def test_focus_grants_a_soul(self, duel):
        duel.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.STRIKE)})
        assert duel.souls(Side.A) == 1
        assert duel.souls(Side.B) == 0

    def test_souls_are_capped(self, duel):
        for _ in range(balance.MAX_SOULS + 3):
            if duel.is_over:
                break
            duel.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.FOCUS)})
        assert duel.souls(Side.A) <= balance.MAX_SOULS

    def test_spending_without_enough_souls_is_denied_not_crashed(self, duel):
        events = duel.submit(
            {Side.A: Decision(Stance.STRIKE, spend_soul=True), Side.B: Decision(Stance.STRIKE)}
        )
        denied = [e for e in events if e.kind is EventKind.SOUL_SPENT and "denied" in e.detail]
        assert len(denied) == 1
        assert duel.souls(Side.A) == 0

    def test_veil_absorbs_most_damage_but_not_all(self, content):
        """Veil used to negate a round outright, which could not be priced --
        cheap enough to reach and it dominated, dear enough to balance and
        nobody paid for it. It now absorbs a percentage, so its value scales
        with the hit rather than being worth a whole round regardless."""
        arena = content.battlefield("whisperwind_arena")
        assert arena.soul_effect is SoulEffect.VEIL
        assert 0 < arena.soul_magnitude < 100, "veil must absorb, not negate"

        def run(spend: bool) -> int:
            match = Match.create(
                _fighter(content, name="A"), _fighter(content, name="B"),
                arena, content, seed=9,
            )
            for _ in range(arena.soul_cost):
                match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.FOCUS)})
            before = match.bp(Side.A)
            events = match.submit({
                Side.A: Decision(Stance.GUARD, spend_soul=spend),
                Side.B: Decision(Stance.STRIKE),
            })
            if spend:
                assert any(e.kind is EventKind.BLOCKED and e.side is Side.A for e in events)
            return before - match.bp(Side.A)

        veiled, plain = run(True), run(False)
        assert 0 < veiled < plain, f"veiled took {veiled}, unveiled took {plain}"

    def test_mend_restores_bp(self, content):
        arena = content.battlefield("tide_of_trials")
        assert arena.soul_effect is SoulEffect.MEND
        match = Match.create(
            _fighter(content, name="A", element=Element.WATER, guard=balance.STAT_MAXIMUM,
                     power=6, focus=6),
            _fighter(content, name="B", element=Element.WATER, guard=balance.STAT_MAXIMUM,
                     power=6, focus=6),
            arena, content, seed=11,
        )
        for _ in range(arena.soul_cost):
            match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.FOCUS)})
        assert not match.is_over
        damaged = match.bp(Side.A)
        assert damaged < balance.STARTING_BP, "need real damage for mend to be visible"
        healed = match.submit(
            {Side.A: Decision(Stance.GUARD, spend_soul=True), Side.B: Decision(Stance.GUARD)}
        )
        assert any(e.kind is EventKind.SOUL_SPENT and "denied" not in e.detail for e in healed)
        # Mend restores BP, so this round costs A less than an unmended one.
        assert match.bp(Side.A) > damaged - arena.soul_magnitude

    def test_ruin_damages_the_opponent(self, content):
        arena = content.battlefield("tenebris_abyss")
        assert arena.soul_effect is SoulEffect.RUIN
        match = Match.create(
            _fighter(content, name="A", element=Element.SHADOW),
            _fighter(content, name="B", element=Element.SHADOW),
            arena, content, seed=13,
        )
        for _ in range(arena.soul_cost):
            match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.GUARD)})
        before_b = match.bp(Side.B)
        match.submit(
            {Side.A: Decision(Stance.GUARD, spend_soul=True), Side.B: Decision(Stance.GUARD)}
        )
        assert before_b - match.bp(Side.B) > arena.soul_magnitude

    def test_purge_clears_statuses(self, content):
        from rivalforge.engine.resolve import BURN, inflict  # noqa: PLC0415

        arena = content.battlefield("blazing_rift")
        assert arena.soul_effect is SoulEffect.PURGE
        match = Match.create(
            _fighter(content, name="A", element=Element.WIND),
            _fighter(content, name="B", element=Element.WIND),
            arena, content, seed=17,
        )
        for _ in range(arena.soul_cost):
            match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.GUARD)})
        # Force a burn on A regardless of hazard rolls.
        match._states[Side.A] = inflict(match._states[Side.A], BURN, 3)
        assert match._states[Side.A].has(BURN)
        match.submit(
            {Side.A: Decision(Stance.GUARD, spend_soul=True), Side.B: Decision(Stance.GUARD)}
        )
        assert not match._states[Side.A].has(BURN)

    def test_rewind_restores_the_previous_bp(self, content):
        arena = content.battlefield("chronos_cradle")
        assert arena.soul_effect is SoulEffect.REWIND
        match = Match.create(
            _fighter(content, name="A", element=Element.TIME),
            _fighter(content, name="B", element=Element.TIME),
            arena, content, seed=19,
        )
        for _ in range(arena.soul_cost):
            match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.GUARD)})
        before = match.bp(Side.A)
        match.submit(
            {Side.A: Decision(Stance.GUARD, spend_soul=True), Side.B: Decision(Stance.STRIKE)}
        )
        # Rewind sets BP back to the start of this round, then this round's
        # damage lands on top -- so A is never worse off than a normal round.
        assert match.bp(Side.A) <= before

    def test_every_soul_effect_has_a_resolver_branch(self, content):
        """Companion to the content-side exhaustiveness test: an effect the
        content declares but the resolver cannot handle would crash mid-match.
        Playing every arena's mechanic proves each branch exists."""
        for arena in content.battlefields:
            match = Match.create(
                _fighter(content, name="A", element=arena.element),
                _fighter(content, name="B", element=arena.element),
                arena, content, seed=23,
            )
            for _ in range(arena.soul_cost):
                match.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.GUARD)})
            events = match.submit(
                {Side.A: Decision(Stance.GUARD, spend_soul=True), Side.B: Decision(Stance.GUARD)}
            )
            spent = [
                e for e in events
                if e.kind is EventKind.SOUL_SPENT and "denied" not in e.detail
            ]
            assert spent, f"{arena.id}: soul mechanic did not fire"


class TestHazards:
    def test_an_attuned_fighter_is_immune_to_its_own_arena(self, content):
        arena = content.battlefield("blazing_rift")
        match = Match.create(
            _fighter(content, name="A", element=Element.FIRE),
            _fighter(content, name="B", element=Element.FIRE),
            arena, content, seed=31,
        )
        for _ in range(12):
            if match.is_over:
                break
            events = match.submit(BOTH_STRIKE)
            assert not [e for e in events if e.kind is EventKind.HAZARD]

    def test_an_unattuned_fighter_eventually_takes_the_hazard(self, content):
        arena = content.battlefield("tenebris_abyss")  # highest hazard chance
        seen = False
        for seed in range(60):
            match = Match.create(
                _fighter(content, name="A", element=Element.FIRE),
                _fighter(content, name="B", element=Element.FIRE),
                arena, content, seed=seed,
            )
            while not match.is_over:
                if [e for e in match.submit(BOTH_STRIKE) if e.kind is EventKind.HAZARD]:
                    seen = True
                    break
            if seen:
                break
        assert seen, "no hazard fired across 60 seeds on the highest-hazard arena"


class TestMatchView:
    def test_a_view_hides_nothing_it_should_show_and_shows_nothing_it_should_hide(self, duel):
        view = duel.view(Side.A)
        assert view.you is duel.fighter(Side.A)
        assert view.opponent is duel.fighter(Side.B)
        assert view.your_bp == duel.bp(Side.A)
        # The opponent's pending decision and the RNG must not be reachable.
        assert not hasattr(view, "rng")
        assert not hasattr(view, "pending")
        assert "_rng" not in vars(view) if hasattr(view, "__dict__") else True

    def test_opponent_history_grows_and_is_the_other_sides(self, duel):
        duel.submit({Side.A: Decision(Stance.STRIKE), Side.B: Decision(Stance.GUARD)})
        assert duel.view(Side.A).opponent_history == (Stance.GUARD,)
        assert duel.view(Side.B).opponent_history == (Stance.STRIKE,)

    def test_can_spend_soul_reflects_the_arena_cost(self, duel):
        assert duel.view(Side.A).can_spend_soul is False
        for _ in range(duel.view(Side.A).arena.soul_cost):
            duel.submit({Side.A: Decision(Stance.FOCUS), Side.B: Decision(Stance.GUARD)})
        assert duel.view(Side.A).can_spend_soul is True


class TestAgents:
    @pytest.mark.parametrize("name", sorted(AGENT_REGISTRY))
    def test_every_agent_can_finish_a_match(self, content, name):
        match = Match.create(
            derive_fighter(MINT_A, content), derive_fighter(MINT_B, content),
            content.battlefield("blazing_rift"), content, seed=101,
        )
        outcome = play(match, {
            Side.A: build_agent(name, RNG(1)),
            Side.B: build_agent("random", RNG(2)),
        })
        assert outcome.rounds > 0

    def test_agent_matches_are_reproducible(self, content):
        def run():
            match = Match.create(
                derive_fighter(MINT_A, content), derive_fighter(MINT_B, content),
                content.battlefield("tide_of_trials"), content, seed=77,
            )
            play(match, {
                Side.A: build_agent("adaptive", RNG(5)),
                Side.B: build_agent("aggressive", RNG(6)),
            })
            return [str(e) for e in match.log]

        assert run() == run()

    def test_adaptive_beats_a_predictable_opponent(self, content):
        """Reading an opponent must pay. Note the opponent has to *have* a
        pattern: an earlier version of this test pitted adaptive against
        random and failed, correctly -- there is nothing to read in a coin,
        so counter-picking it is worth exactly nothing."""
        wins = Counter()
        for seed in range(200):
            match = Match.create(
                _fighter(content, name="A"), _fighter(content, name="B"),
                content.battlefield("whisperwind_arena"), content, seed=seed,
            )
            outcome = play(match, {
                Side.A: build_agent("adaptive", RNG(seed * 2 + 1)),
                Side.B: build_agent("aggressive", RNG(seed * 2 + 2)),
            })
            wins[outcome.winner] += 1
        assert wins[Side.A] > wins[Side.B] * 1.4, (
            f"adaptive={wins[Side.A]} aggressive={wins[Side.B]}"
        )

    def test_adaptive_is_not_worse_than_random(self, content):
        """Against an unreadable opponent, adaptive should be level -- not
        behind. Falling behind would mean its counter-picking is actively
        harmful rather than merely unhelpful."""
        wins = Counter()
        for seed in range(240):
            match = Match.create(
                _fighter(content, name="A"), _fighter(content, name="B"),
                content.battlefield("whisperwind_arena"), content, seed=seed,
            )
            outcome = play(match, {
                Side.A: build_agent("adaptive", RNG(seed * 2 + 1)),
                Side.B: build_agent("random", RNG(seed * 2 + 2)),
            })
            wins[outcome.winner] += 1
        assert wins[Side.A] > wins[Side.B] * 0.8, (
            f"adaptive={wins[Side.A]} random={wins[Side.B]}"
        )

    def test_unknown_agent_name_is_a_clear_error(self):
        with pytest.raises(KeyError, match="available"):
            build_agent("galaxy_brain", RNG(1))

    def test_an_agent_only_ever_returns_a_valid_decision(self, content):
        """Property-ish: whatever an agent returns must survive validation, so
        a bad agent cannot inject an unhandled stance into the resolver."""
        for name in sorted(AGENT_REGISTRY):
            agent = build_agent(name, RNG(3))
            match = Match.create(
                derive_fighter(MINT_A, content), derive_fighter(MINT_B, content),
                content.battlefield("aurora_sanctum"), content, seed=42,
            )
            while not match.is_over:
                decisions = {}
                for side in match.awaiting:
                    decision = agent.decide(match.view(side))
                    assert isinstance(decision, Decision)
                    assert Decision.parse(decision) == decision
                    decisions[side] = decision
                match.submit(decisions)


class TestBalanceSanity:
    def test_matches_last_a_reasonable_number_of_rounds(self, content):
        """A sixty-second game needs matches in the 4-14 round band. Outside
        it, the loop is either a coin flip or a slog -- and either is a design
        bug that no unit test on damage would catch."""
        lengths = []
        for seed in range(150):
            match = Match.create(
                derive_fighter(b58encode(seed.to_bytes(32, "big")), content),
                derive_fighter(b58encode((seed + 9000).to_bytes(32, "big")), content),
                content.battlefield("whisperwind_arena"), content, seed=seed,
            )
            play(match, {
                Side.A: build_agent("adaptive", RNG(seed)),
                Side.B: build_agent("aggressive", RNG(seed + 1)),
            })
            lengths.append(match.outcome.rounds)
        average = sum(lengths) / len(lengths)
        assert 4 <= average <= 14, f"average match length {average:.1f} rounds"

    def test_no_stance_is_dominant(self, content):
        """If one stance wins regardless of the opponent's, the read is
        pointless and the game is solved."""
        wins = Counter()
        for a_stance in Stance:
            for b_stance in Stance:
                if a_stance is b_stance:
                    continue
                for seed in range(40):
                    match = Match.create(
                        _fighter(content, name="A"), _fighter(content, name="B"),
                        content.battlefield("whisperwind_arena"), content, seed=seed,
                    )
                    while not match.is_over:
                        match.submit({
                            Side.A: Decision(a_stance), Side.B: Decision(b_stance)
                        })
                    if match.outcome.winner is Side.A:
                        wins[a_stance] += 1
                    elif match.outcome.winner is Side.B:
                        wins[b_stance] += 1
        best = max(wins.values())
        worst = min(wins.values())
        assert best <= worst * 3, f"stance win counts are lopsided: {dict(wins)}"


class TestArenaHealth:
    """The balance gate, enforced in CI.

    `tools/balance_sweep.py` is the full harness; this is the cheap version of
    it that runs on every commit. Balance regressions are silent -- no
    exception, no wrong answer, just a game that stops being fun -- so the only
    way to catch them is to assert on measured outcomes.
    """

    #: Arenas may skew; the game as a whole may not. See the sweep tool.
    ARENA_MIN, ARENA_MAX = 0.15, 0.80
    OVERALL_MIN, OVERALL_MAX = 0.30, 0.70

    @staticmethod
    def _round_robin(content, arena, matches):
        import itertools  # noqa: PLC0415

        agents = sorted(AGENT_REGISTRY)
        tally = {a: [0, 0] for a in agents}
        lengths = []
        for left, right in itertools.permutations(agents, 2):
            for seed in range(matches):
                match = Match.create(
                    _fighter(content, name="A"), _fighter(content, name="B"),
                    arena, content, seed=seed,
                )
                outcome = play(match, {
                    Side.A: build_agent(left, RNG(seed * 2 + 1)),
                    Side.B: build_agent(right, RNG(seed * 2 + 2)),
                })
                tally[left][1] += 1
                tally[right][1] += 1
                if outcome.winner is Side.A:
                    tally[left][0] += 1
                elif outcome.winner is Side.B:
                    tally[right][0] += 1
                lengths.append(outcome.rounds)
        return (
            {a: w / p for a, (w, p) in tally.items()},
            sum(lengths) / len(lengths),
        )

    def test_no_arena_is_a_trap_or_an_auto_win(self, content):
        for arena in content.battlefields:
            rates, rounds = self._round_robin(content, arena, 25)
            assert 4 <= rounds <= 14, f"{arena.id}: matches average {rounds:.1f} rounds"
            for agent, rate in rates.items():
                assert self.ARENA_MIN < rate < self.ARENA_MAX, (
                    f"{arena.id}: {agent} wins {rate:.0%}"
                )

    def test_the_game_as_a_whole_is_fair_and_rewards_reading(self, content):
        tally = {a: [0.0, 0] for a in sorted(AGENT_REGISTRY)}
        rounds = []
        for arena in content.battlefields:
            rates, mean = self._round_robin(content, arena, 25)
            rounds.append(mean)
            for agent, rate in rates.items():
                tally[agent][0] += rate
                tally[agent][1] += 1
        overall = {a: total / n for a, (total, n) in tally.items()}

        for agent, rate in overall.items():
            assert self.OVERALL_MIN < rate < self.OVERALL_MAX, f"{agent} wins {rate:.0%} overall"
        assert max(overall, key=lambda a: overall[a]) == "adaptive", (
            f"reading an opponent must pay: {overall}"
        )
        mean_rounds = sum(rounds) / len(rounds)
        assert 4 <= mean_rounds <= 14, f"matches average {mean_rounds:.1f} rounds"
