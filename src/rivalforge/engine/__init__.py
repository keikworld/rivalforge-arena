"""The pure, deterministic combat engine. No I/O lives below this package."""

from . import balance
from .fighter import Fighter, derive_fighter, starter_fighter
from .match import Decision, Event, EventKind, Match, MatchView, Outcome, Side, play
from .resolve import CombatantState, DamageBreakdown, compute_damage
from .rng import RNG, new_seed

__all__ = [
    "CombatantState", "DamageBreakdown", "Decision", "Event", "EventKind", "Fighter",
    "Match", "MatchView", "Outcome", "RNG", "Side", "balance", "compute_damage",
    "derive_fighter", "new_seed", "play", "starter_fighter",
]
