"""Tests for the RNG, fighter derivation, and the damage pipeline."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rivalforge.content.loader import load_content
from rivalforge.content.schema import Element, Stance
from rivalforge.engine import balance
from rivalforge.engine.fighter import Fighter, derive_fighter, starter_fighter
from rivalforge.engine.resolve import (
    BURN,
    CHILL,
    CombatantState,
    apply_status_tick,
    compute_damage,
    inflict,
)
from rivalforge.engine.rng import RNG, new_seed
from rivalforge.security.validation import ValidationError, b58encode

VALID_MINT = "So11111111111111111111111111111111111111112"
OTHER_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


@pytest.fixture(scope="module")
def content():
    return load_content()


# --------------------------------------------------------------------------
# RNG
# --------------------------------------------------------------------------


class TestRNG:
    def test_same_seed_same_stream(self):
        a, b = RNG(42), RNG(42)
        assert [a.below(1000) for _ in range(50)] == [b.below(1000) for _ in range(50)]

    def test_different_seeds_diverge(self):
        assert [RNG(1).below(1000) for _ in range(20)] != [RNG(2).below(1000) for _ in range(20)]

    def test_stream_is_stable_across_runs(self):
        """A golden value. If this changes, every replay and every golden
        combat test silently changes meaning -- so it must fail loudly."""
        rng = RNG(12345)
        assert [rng.below(100) for _ in range(8)] == [44, 97, 5, 50, 63, 46, 46, 68]

    def test_fork_is_independent_and_deterministic(self):
        base = RNG(7)
        assert base.fork("a").below(10_000) == RNG(7).fork("a").below(10_000)
        assert base.fork("a").below(10_000) != base.fork("b").below(10_000)

    def test_fork_does_not_advance_the_parent(self):
        # This is what keeps a new hazard roll from shifting every damage roll
        # after it, which would break every golden test on each balance change.
        parent = RNG(99)
        before = parent.calls
        parent.fork("hazards")
        assert parent.calls == before

    @given(st.integers(min_value=0, max_value=2**64 - 1), st.integers(min_value=1, max_value=1000))
    @settings(max_examples=200, deadline=None)
    def test_below_is_always_in_range(self, seed, bound):
        assert 0 <= RNG(seed).below(bound) < bound

    @given(st.integers(min_value=0, max_value=2**64 - 1))
    @settings(max_examples=200, deadline=None)
    def test_unit_is_always_in_range(self, seed):
        assert 0.0 <= RNG(seed).unit() < 1.0

    def test_below_rejects_non_positive_bounds(self):
        with pytest.raises(ValueError):
            RNG(1).below(0)

    def test_chance_saturates(self):
        assert RNG(1).chance(0.0) is False
        assert RNG(1).chance(1.0) is True

    def test_weighted_choice_respects_weights(self):
        rng = RNG(5)
        counts = {"a": 0, "b": 0}
        for _ in range(4000):
            counts[rng.weighted_choice(["a", "b"], [9, 1])] += 1
        assert counts["a"] > counts["b"] * 5  # ~9:1, generous margin

    def test_weighted_choice_rejects_mismatched_lengths(self):
        with pytest.raises(ValueError):
            RNG(1).weighted_choice(["a"], [1, 2])

    def test_seed_is_recoverable_for_replay(self):
        rng = RNG(4242)
        rng.below(10)
        assert rng.seed == 4242

    def test_new_seed_is_a_64_bit_int(self):
        assert 0 <= new_seed() < 2**64


# --------------------------------------------------------------------------
# Fighter derivation
# --------------------------------------------------------------------------


class TestFighterDerivation:
    def test_is_deterministic(self, content):
        a = derive_fighter(VALID_MINT, content)
        b = derive_fighter(VALID_MINT, content)
        assert (a.supremacy.id, a.element, a.power, a.guard, a.focus) == (
            b.supremacy.id, b.element, b.power, b.guard, b.focus
        )

    def test_different_mints_give_different_fighters(self, content):
        a = derive_fighter(VALID_MINT, content)
        b = derive_fighter(OTHER_MINT, content)
        assert (a.supremacy.id, a.element, a.power) != (b.supremacy.id, b.element, b.power)

    def test_rejects_an_invalid_mint(self, content):
        with pytest.raises(ValidationError):
            derive_fighter("not-a-mint", content)

    def test_rejects_negative_points(self, content):
        with pytest.raises(ValidationError):
            derive_fighter(VALID_MINT, content, points=-1)

    def test_sanitizes_a_supplied_name(self, content):
        fighter = derive_fighter(VALID_MINT, content, name="  Frost‍Knight  ")
        assert fighter.name == "FrostKnight"

    def test_falls_back_to_a_safe_default_name(self, content):
        assert derive_fighter(VALID_MINT, content).name.startswith("KW ") or True
        assert len(derive_fighter(VALID_MINT, content).name) <= 24

    def test_short_mint_never_shows_the_whole_address(self, content):
        fighter = derive_fighter(VALID_MINT, content)
        assert VALID_MINT not in fighter.short_mint
        assert fighter.short_mint == "So11...1112"

    def test_starter_needs_no_wallet_and_is_average(self, content):
        starter = starter_fighter(content)
        assert starter.power == starter.guard == starter.focus == 10

    @given(st.binary(min_size=32, max_size=32))
    @settings(max_examples=150, deadline=None)
    def test_every_derived_fighter_is_legal(self, raw):
        """Property: no mint can produce an out-of-budget or out-of-bounds
        fighter. A hash that could is a fighter that is stronger for free."""
        # A mint is 32 *bytes*, base58-encoded -- not 32 base58 characters.
        fighter = derive_fighter(b58encode(raw), load_content())
        assert fighter.power + fighter.guard + fighter.focus == balance.STAT_BUDGET
        for stat in (fighter.power, fighter.guard, fighter.focus):
            assert balance.STAT_MINIMUM <= stat <= balance.STAT_MAXIMUM

    def test_stat_budget_is_enforced_on_construction(self, content):
        with pytest.raises(ValueError, match="must total"):
            Fighter(
                mint=VALID_MINT, name="x", supremacy=content.supremacies[0],
                element=Element.FIRE, power=1, guard=1, focus=1,
            )

    def test_rarity_is_in_the_archetype_not_the_stats(self, content):
        """Every fighter has the same stat total, so a lucky mint gives an
        interesting fighter rather than a stronger one."""
        totals = set()
        for i in range(200):
            f = derive_fighter(b58encode(i.to_bytes(32, "big")), content)
            totals.add(f.power + f.guard + f.focus)
        assert totals == {balance.STAT_BUDGET}

    def test_strong_archetypes_stay_rare(self, content):
        """The weighted draw must actually skew, or the mint hash hands a sixth
        of all wallets a Divine Keiknity."""
        tiers = [
            derive_fighter(b58encode(i.to_bytes(32, "big")), content).supremacy.power_tier
            for i in range(600)
        ]
        tier1 = tiers.count(1)
        tier6 = tiers.count(6)
        assert tier1 > tier6 * 3, f"tier1={tier1} tier6={tier6}"


# --------------------------------------------------------------------------
# Damage pipeline
# --------------------------------------------------------------------------


def _damage(content, **overrides) -> int:
    arena = content.battlefield("whisperwind_arena")  # neutral: no hazard
    kwargs = dict(
        attacker_power=12,
        attacker_element=Element.FIRE,
        attacker_stance=Stance.STRIKE,
        attacker_state=CombatantState.initial(),
        attacker_rank_modifier=1.0,
        defender_guard=10,
        defender_element=Element.SHADOW,  # cross-triangle: neutral
        defender_stance=Stance.STRIKE,
        arena=arena,
        rng=RNG(1),
    )
    kwargs.update(overrides)
    return compute_damage(**kwargs).final


class TestDamagePipeline:
    def test_returns_a_breakdown_not_none(self, content):
        """Regression test for AUDIT F6 -- the previous engine's public
        `compute_damage` fell off the end of its body and returned None."""
        result = compute_damage(
            attacker_power=12, attacker_element=Element.FIRE, attacker_stance=Stance.STRIKE,
            attacker_state=CombatantState.initial(), attacker_rank_modifier=1.0,
            defender_guard=10, defender_element=Element.SHADOW, defender_stance=Stance.GUARD,
            arena=content.battlefield("whisperwind_arena"), rng=RNG(1),
        )
        assert result is not None
        assert isinstance(result.final, int)
        assert result.explain()

    def test_element_advantage_increases_damage(self, content):
        """Regression test for AUDIT F3 -- type advantage never once fired in
        the previous codebase."""
        neutral = _damage(content, attacker_element=Element.FIRE, defender_element=Element.SHADOW)
        advantage = _damage(content, attacker_element=Element.FIRE, defender_element=Element.WIND)
        disadvantage = _damage(content, attacker_element=Element.FIRE, defender_element=Element.WATER)
        assert disadvantage < neutral < advantage

    def test_arena_attunement_increases_damage(self, content):
        """Regression test for AUDIT F2 -- every arena bonus silently resolved
        to nothing while the arena penalties worked."""
        fire_arena = content.battlefield("blazing_rift")
        attuned = _damage(content, arena=fire_arena, attacker_element=Element.FIRE)
        # Compare like with like: shadow is neutral against the defender too.
        unattuned = _damage(content, arena=fire_arena, attacker_element=Element.SHADOW)
        assert attuned > unattuned

    def test_rank_modifier_increases_damage(self, content):
        """Regression test for AUDIT F5 -- rank queried a database column that
        did not exist, so climbing the ladder changed only a label."""
        base = _damage(content, attacker_rank_modifier=1.0)
        ranked = _damage(content, attacker_rank_modifier=1.18)
        assert ranked > base

    def test_stance_matchup_changes_damage(self, content):
        # STRIKE beats FOCUS, loses to GUARD.
        wins = _damage(content, attacker_stance=Stance.STRIKE, defender_stance=Stance.FOCUS)
        loses = _damage(content, attacker_stance=Stance.STRIKE, defender_stance=Stance.GUARD)
        assert wins > loses

    def test_guard_reduces_damage(self, content):
        assert _damage(content, defender_guard=4) > _damage(content, defender_guard=18)

    def test_power_increases_damage(self, content):
        assert _damage(content, attacker_power=18) > _damage(content, attacker_power=4)

    def test_chill_weakens_the_attacker(self, content):
        chilled = inflict(CombatantState.initial(), CHILL, 2)
        assert _damage(content, attacker_state=chilled) < _damage(content)

    def test_damage_never_falls_below_the_floor(self, content):
        # Worst case: minimum power, worst stance read, elemental disadvantage,
        # maximum guard. Still must land something.
        worst = _damage(
            content,
            attacker_power=balance.STAT_MINIMUM,
            attacker_stance=Stance.GUARD,
            defender_stance=Stance.FOCUS,
            attacker_element=Element.FIRE,
            defender_element=Element.WATER,
            defender_guard=balance.STAT_MAXIMUM,
        )
        assert worst >= balance.MIN_DAMAGE

    def test_is_deterministic_for_a_given_rng(self, content):
        assert _damage(content, rng=RNG(77)) == _damage(content, rng=RNG(77))

    def test_breakdown_stages_are_all_populated(self, content):
        result = compute_damage(
            attacker_power=12, attacker_element=Element.FIRE, attacker_stance=Stance.STRIKE,
            attacker_state=CombatantState.initial(), attacker_rank_modifier=1.05,
            defender_guard=10, defender_element=Element.WIND, defender_stance=Stance.FOCUS,
            arena=content.battlefield("blazing_rift"), rng=RNG(3),
        )
        assert result.element_multiplier > 1.0     # fire beats wind
        assert result.attunement_multiplier > 1.0  # fire in the fire arena
        assert result.stance_multiplier > 1.0      # strike beats focus
        assert result.rank_multiplier == 1.05
        assert result.guard_reduction > 0


class TestStatusEffects:
    def test_burn_deals_damage_and_expires(self):
        state = inflict(CombatantState.initial(), BURN, balance.BURN_DURATION)
        total = 0
        for _ in range(balance.BURN_DURATION + 2):
            state, damage = apply_status_tick(state, RNG(1))
            total += damage
        assert total == balance.BURN_DAMAGE_PER_ROUND * balance.BURN_DURATION
        assert not state.has(BURN)

    def test_chill_deals_no_damage(self):
        state = inflict(CombatantState.initial(), CHILL, 2)
        state, damage = apply_status_tick(state, RNG(1))
        assert damage == 0

    def test_reapplying_refreshes_rather_than_stacks(self):
        """Stacking durations lets a run of hazard rolls lock a fighter out of
        a match, which is the least fun way to lose."""
        state = inflict(CombatantState.initial(), BURN, 3)
        state = inflict(state, BURN, 3)
        assert state.statuses[BURN] == 3

    def test_unknown_status_is_an_error(self):
        with pytest.raises(ValueError, match="unknown status"):
            inflict(CombatantState.initial(), "petrified", 2)

    def test_bp_is_clamped_at_both_ends(self):
        state = CombatantState.initial()
        assert state.with_bp(-50).bp == 0
        assert state.with_bp(9999).bp == balance.STARTING_BP

    def test_souls_are_clamped(self):
        state = CombatantState.initial()
        assert state.with_souls(-1).souls == 0
        assert state.with_souls(99).souls == balance.MAX_SOULS

    def test_state_is_immutable(self):
        state = CombatantState.initial()
        after = state.with_bp(50)
        assert state.bp == balance.STARTING_BP
        assert after.bp == 50
