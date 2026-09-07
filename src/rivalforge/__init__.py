"""RivalForge -- a sixty-second NFT duelling game.

Public surface. Import from here rather than from submodules, so internal
layout can change without breaking callers.
"""

from .content.loader import ContentError, load_content
from .content.schema import Element, GameContent, Stance
from .engine.fighter import Fighter, derive_fighter, starter_fighter
from .engine.match import Decision, Event, EventKind, Match, Outcome, Side, play
from .engine.rng import RNG, new_seed
from .security.validation import ValidationError

__version__ = "0.1.0"

__all__ = [
    "ContentError",
    "Decision",
    "Element",
    "Event",
    "EventKind",
    "Fighter",
    "GameContent",
    "Match",
    "Outcome",
    "RNG",
    "Side",
    "Stance",
    "ValidationError",
    "__version__",
    "derive_fighter",
    "load_content",
    "new_seed",
    "play",
    "starter_fighter",
]
