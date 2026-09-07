"""Combat resolution: the pure maths of one round.

Everything here is a function of its arguments. No I/O, no clock, no global
state, no logging. Given the same inputs and the same `RNG`, these functions
return the same result on any machine, forever.

That constraint is what makes the rest possible: exact unit tests, replayable
matches, AI agents that can search ahead, and a server that can re-run a
disputed match to settle it.

The damage pipeline, in order. Each step is a named function so a balance
change has one obvious home and a test can pin each stage independently:

    1. base attack        stats and stance
    2. status             chill weakens the attacker
    3. stance matchup     the read: strike / guard / focus triangle
    4. element matchup    the two element triangles
    5. attunement         the arena favours its own element
    6. rank               ladder progression, which *does* affect damage here
    7. variance           a narrow random spread
    8. guard              the defender subtracts, after everything above
    9. floor              a hit is never zero
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Final, Mapping

from ..content.schema import (
    Battlefield,
    Element,
    Stance,
    element_multiplier,
    stance_multiplier,
)
from . import balance
from .rng import RNG

__all__ = [
    "BURN",
    "CHILL",
    "CombatantState",
    "DamageBreakdown",
    "compute_damage",
    "apply_status_tick",
    "inflict",
]

#: Status effect identifiers. Strings rather than an enum because battlefield
#: content names them, and the loader validates the name against this set.
BURN: Final = "burn"
CHILL: Final = "chill"

KNOWN_STATUSES: Final = frozenset({BURN, CHILL})


@dataclass(frozen=True, slots=True)
class CombatantState:
    """One fighter's mutable-per-round state, held immutably.

    Every transition returns a new instance. Nothing mutates in place, so a
    caller can keep the previous round's state for free -- which is exactly
    what the Chronos Cradle rewind mechanic needs, and what makes a replay log
    a list of states rather than a list of guesses.
    """

    bp: int
    souls: int
    #: status id -> rounds remaining
    statuses: Mapping[str, int]
    #: BP at the start of the previous round, for `rewind`.
    previous_bp: int

    @classmethod
    def initial(cls) -> "CombatantState":
        return cls(
            bp=balance.STARTING_BP,
            souls=0,
            statuses={},
            previous_bp=balance.STARTING_BP,
        )

    @property
    def is_down(self) -> bool:
        return self.bp <= 0

    def has(self, status: str) -> bool:
        return self.statuses.get(status, 0) > 0

    def with_bp(self, bp: int) -> "CombatantState":
        """Set BP, clamped to ``[0, STARTING_BP]``.

        Clamping here rather than at each call site means no path can produce
        a negative bar or heal past the maximum, however the value was reached.
        """
        return replace(self, bp=max(0, min(balance.STARTING_BP, bp)))

    def with_souls(self, souls: int) -> "CombatantState":
        return replace(self, souls=max(0, min(balance.MAX_SOULS, souls)))


@dataclass(frozen=True, slots=True)
class DamageBreakdown:
    """Every stage of one damage calculation, kept for tests and for the UI.

    The previous codebase computed damage through a chain of silent multipliers
    and no one could tell which of them were firing -- several were not. A
    breakdown that is returned rather than logged makes each stage assertable.
    """

    base: float
    status_multiplier: float
    stance_multiplier: float
    element_multiplier: float
    attunement_multiplier: float
    rank_multiplier: float
    variance_multiplier: float
    guard_reduction: float
    final: int

    def explain(self) -> str:
        """A one-line trace, for the CLI's verbose mode."""
        return (
            f"base {self.base:.1f}"
            f" x status {self.status_multiplier:.2f}"
            f" x stance {self.stance_multiplier:.2f}"
            f" x element {self.element_multiplier:.2f}"
            f" x arena {self.attunement_multiplier:.2f}"
            f" x rank {self.rank_multiplier:.2f}"
            f" x var {self.variance_multiplier:.2f}"
            f" - guard {self.guard_reduction:.1f}"
            f" = {self.final}"
        )


def _base_attack(power: int, stance: Stance) -> float:
    """Stage 1: raw attack from the fighter's power and chosen stance."""
    return balance.BASE_DAMAGE + power * balance.POWER_SCALING * balance.STANCE_ATTACK[stance]


def _status_multiplier(state: CombatantState) -> float:
    """Stage 2: chill weakens the attacker. Burn does not -- it bites at the
    end of the round instead, so the two hazards feel different in play."""
    return balance.CHILL_ATTACK_PENALTY if state.has(CHILL) else 1.0


def _attunement_multiplier(element: Element, arena: Battlefield) -> float:
    """Stage 5: the arena's bonus for a fighter of its own element.

    This is the bug from the previous codebase that mattered most: the arena
    bonus was read under a key the content did not have, so it silently
    resolved to nothing while the arena *penalties* worked fine. Here the value
    comes from a typed, schema-validated field, and a test asserts it changes
    the damage.
    """
    return arena.attunement_bonus if element is arena.element else 1.0


def _guard_reduction(guard: int, stance: Stance) -> float:
    """Stage 8: flat reduction applied after every multiplier.

    Subtractive rather than a further multiplier, so guard is strongest against
    the many small hits it is meant to blunt and weakest against the big ones
    it is meant to lose to.
    """
    return guard * balance.GUARD_SCALING * balance.STANCE_DEFENCE[stance]


def compute_damage(
    *,
    attacker_power: int,
    attacker_element: Element,
    attacker_stance: Stance,
    attacker_state: CombatantState,
    attacker_rank_modifier: float,
    defender_guard: int,
    defender_element: Element,
    defender_stance: Stance,
    arena: Battlefield,
    rng: RNG,
) -> DamageBreakdown:
    """Compute one fighter's damage against the other for this round.

    Returns the full breakdown rather than a bare number, so callers can show
    the player why a hit landed the way it did and tests can pin each stage.
    """
    base = _base_attack(attacker_power, attacker_stance)
    status = _status_multiplier(attacker_state)
    stance = stance_multiplier(attacker_stance, defender_stance)
    element = element_multiplier(attacker_element, defender_element)
    attunement = _attunement_multiplier(attacker_element, arena)
    rank = attacker_rank_modifier
    variance = rng.between(1.0 - balance.DAMAGE_VARIANCE, 1.0 + balance.DAMAGE_VARIANCE)

    raw = base * status * stance * element * attunement * rank * variance
    reduction = _guard_reduction(defender_guard, defender_stance)
    final = max(balance.MIN_DAMAGE, int(round(raw - reduction)))

    return DamageBreakdown(
        base=base,
        status_multiplier=status,
        stance_multiplier=stance,
        element_multiplier=element,
        attunement_multiplier=attunement,
        rank_multiplier=rank,
        variance_multiplier=variance,
        guard_reduction=reduction,
        final=final,
    )


def inflict(state: CombatantState, status: str, duration: int) -> CombatantState:
    """Apply a status effect, refreshing rather than stacking its duration.

    Refresh, not stack: stacking durations lets a lucky run of hazard rolls
    lock a fighter out of a match, which is the least fun way to lose.

    Raises:
        ValueError: on an unknown status id. Content is validated at load, so
            reaching this means an engine bug, and it should be loud.
    """
    if status not in KNOWN_STATUSES:
        raise ValueError(f"unknown status effect: {status!r}")
    updated = dict(state.statuses)
    updated[status] = max(updated.get(status, 0), duration)
    return replace(state, statuses=updated)


def apply_status_tick(state: CombatantState, rng: RNG) -> tuple[CombatantState, int]:
    """End-of-round status damage and expiry.

    Returns the new state and the damage dealt by statuses this round.

    `rng` is accepted but unused today. It is in the signature because status
    damage is the next thing likely to gain a roll, and adding a parameter to a
    function every caller already threads an RNG into is a smaller change than
    adding one to a signature that never had it.
    """
    del rng  # reserved; see docstring

    damage = 0
    remaining: dict[str, int] = {}
    for status, rounds_left in state.statuses.items():
        if rounds_left <= 0:
            continue
        if status == BURN:
            damage += balance.BURN_DAMAGE_PER_ROUND
        if rounds_left - 1 > 0:
            remaining[status] = rounds_left - 1

    ticked = replace(state, statuses=remaining)
    if damage:
        ticked = ticked.with_bp(ticked.bp - damage)
    return ticked, damage
