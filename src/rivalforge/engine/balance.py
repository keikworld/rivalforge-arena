"""Every tunable number in combat, in one file.

Balance lives apart from logic on purpose. Tuning a game means changing these
numbers often, and mixing them into the resolver is how a codebase ends up with
the same constant written four times with three different values.

Nothing here is read from the environment or a database. A match's numbers are
a property of the build, so two players on the same version cannot be playing
two different games.
"""

from __future__ import annotations

from typing import Final

from ..content.schema import Stance

# --------------------------------------------------------------------------
# Match shape
# --------------------------------------------------------------------------

#: Starting battle points. 100 is the number the original game used and it is
#: still the right one: damage lands in the 10-25 range, so a match is 6-10
#: rounds -- long enough to read your opponent, short enough for a phone.
STARTING_BP: Final = 100

#: Hard stop, so a pathological pair of defensive agents cannot loop forever.
#: Reaching it is a draw, decided on remaining BP.
MAX_ROUNDS: Final = 30

#: Souls are the depth layer. Capped low so they are a decision, not a meter
#: to farm.
MAX_SOULS: Final = 3
SOUL_GAIN_ON_FOCUS: Final = 1

# --------------------------------------------------------------------------
# Fighter derivation
# --------------------------------------------------------------------------

#: Points distributed across power / guard / focus.
STAT_BUDGET: Final = 30
STAT_MINIMUM: Final = 4
STAT_MAXIMUM: Final = 18

#: Draw weights by supremacy power tier (index 0 is tier 1). Rarer archetypes
#: are stronger, so they must be rarer -- otherwise the mint hash hands out
#: Divine Keiknities to a sixth of all wallets.
SUPREMACY_TIER_WEIGHTS: Final = (40, 26, 16, 10, 6, 2)

# --------------------------------------------------------------------------
# Damage
# --------------------------------------------------------------------------

#: Damage everyone deals regardless of stats, so a low-power fighter is never
#: harmless and a match cannot stall.
BASE_DAMAGE: Final = 6.0

#: Each point of power adds this much raw attack.
POWER_SCALING: Final = 0.9

#: Each point of guard subtracts this much, after multipliers.
GUARD_SCALING: Final = 0.55

#: Per-stance attack and defence weighting. The stance triangle in
#: `content.schema` decides who wins the read; these decide what winning it
#: is worth.
#: Tuned by sweep, not by feel. `tools/balance_sweep.py` runs every agent
#: pairing on every arena and reports win rates and match length; these are the
#: values where all four agents stay viable (42-48%), the adaptive agent is
#: clearly but not overwhelmingly best (66%), and matches average ~10 rounds.
STANCE_ATTACK: Final[dict[Stance, float]] = {
    Stance.STRIKE: 1.35,
    Stance.GUARD: 0.55,
    Stance.FOCUS: 0.70,
}
STANCE_DEFENCE: Final[dict[Stance, float]] = {
    Stance.STRIKE: 0.55,
    Stance.GUARD: 1.30,
    Stance.FOCUS: 0.90,
}

#: Random spread applied to every hit, so identical rounds are not identical.
#: Deliberately narrow: wide variance makes a skilful read feel irrelevant.
DAMAGE_VARIANCE: Final = 0.10

#: A hit never rounds to nothing. Zero-damage rounds read as a bug to players
#: even when the arithmetic is right.
MIN_DAMAGE: Final = 1

# --------------------------------------------------------------------------
# Status effects
# --------------------------------------------------------------------------

#: Burn deals damage at the end of each round and expires on its own.
BURN_DAMAGE_PER_ROUND: Final = 4
BURN_DURATION: Final = 3

#: Chill weakens attacks instead of dealing damage, so the two hazards feel
#: different rather than being one effect with two names.
CHILL_ATTACK_PENALTY: Final = 0.80
CHILL_DURATION: Final = 2

# --------------------------------------------------------------------------
# Progression
# --------------------------------------------------------------------------

POINTS_ON_WIN: Final = 15
POINTS_ON_LOSS: Final = -5
