"""Typed, validated game content.

This module exists because of three bugs in the previous codebase, all of the
same shape: the code read a key the data file did not have, got `None`, and
carried on. Battlefield bonuses, elemental advantage and rank damage modifiers
were all silently dead for the life of the project.

The structural fix is here, and it is one rule:

    **Content is parsed into frozen typed objects at load time, and any
    mismatch between the file and the schema is a hard error before the
    game starts.**

That means a renamed key, a missing key, an unexpected extra key, a value out
of range, or a cross-reference to something that does not exist all stop the
process at import with a message naming the field. There is no path by which
content drift can reach the combat maths.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Mapping

from ..security.validation import (
    ValidationError,
    validate_choice,
    validate_float,
    validate_identifier,
    validate_int,
    validate_text_field,
)

__all__ = [
    "Element",
    "Stance",
    "SoulEffect",
    "Battlefield",
    "Supremacy",
    "Rank",
    "TauntSet",
    "GameContent",
    "beats",
    "element_multiplier",
    "stance_multiplier",
]


# --------------------------------------------------------------------------
# The single element vocabulary
# --------------------------------------------------------------------------


class Element(str, Enum):
    """The one and only name for an element.

    The previous codebase had three incompatible vocabularies for this concept
    across three data files, with an empty intersection, so the type-advantage
    check could never be true. There is now exactly one, it is an enum, and
    content that names an element outside it fails to load.
    """

    FIRE = "fire"
    WATER = "water"
    WIND = "wind"
    LIGHT = "light"
    SHADOW = "shadow"
    TIME = "time"


#: Two disjoint three-cycles. Every element beats exactly one and loses to
#: exactly one, so no element is a dead pick and the whole table fits in a
#: player's head after one match.
_BEATS: Final[Mapping[Element, Element]] = {
    Element.FIRE: Element.WIND,
    Element.WIND: Element.WATER,
    Element.WATER: Element.FIRE,
    Element.LIGHT: Element.SHADOW,
    Element.SHADOW: Element.TIME,
    Element.TIME: Element.LIGHT,
}

#: Damage multiplier when the attacker's element beats the defender's.
ELEMENT_ADVANTAGE: Final = 1.30
#: Damage multiplier when the attacker's element loses to the defender's.
ELEMENT_DISADVANTAGE: Final = 0.80


def beats(attacker: Element, defender: Element) -> bool:
    """True when `attacker`'s element has the advantage over `defender`'s."""
    return _BEATS[attacker] is defender


def element_multiplier(attacker: Element, defender: Element) -> float:
    """The attacker's damage multiplier for this element matchup.

    Cross-triangle matchups (fire against shadow, say) are deliberately
    neutral: a 6x6 table where every cell is non-neutral is unreadable.
    """
    if beats(attacker, defender):
        return ELEMENT_ADVANTAGE
    if beats(defender, attacker):
        return ELEMENT_DISADVANTAGE
    return 1.0


# --------------------------------------------------------------------------
# Stances
# --------------------------------------------------------------------------


class Stance(str, Enum):
    """What a fighter commits to for one round, chosen simultaneously.

    A three-cycle, like the elements, so there is no dominant stance and the
    read is about your opponent rather than about the table.
    """

    STRIKE = "strike"
    GUARD = "guard"
    FOCUS = "focus"


_STANCE_BEATS: Final[Mapping[Stance, Stance]] = {
    Stance.STRIKE: Stance.FOCUS,
    Stance.FOCUS: Stance.GUARD,
    Stance.GUARD: Stance.STRIKE,
}

#: Damage multiplier for winning / losing the stance read.
STANCE_ADVANTAGE: Final = 1.40
STANCE_DISADVANTAGE: Final = 0.68


def stance_multiplier(attacker: Stance, defender: Stance) -> float:
    """The attacker's damage multiplier for this stance matchup."""
    if _STANCE_BEATS[attacker] is defender:
        return STANCE_ADVANTAGE
    if _STANCE_BEATS[defender] is attacker:
        return STANCE_DISADVANTAGE
    return 1.0


# --------------------------------------------------------------------------
# Content objects
# --------------------------------------------------------------------------


class SoulEffect(str, Enum):
    """What a battlefield's soul mechanic does when a fighter spends Soul.

    An enum rather than free text, so a battlefield cannot name an effect the
    engine has no branch for. Adding a battlefield with a new effect requires
    adding the member here and the branch in the resolver -- the type checker
    and the exhaustiveness test both notice if you forget.
    """

    #: Restore battle points, capped at the starting maximum.
    MEND = "mend"
    #: Clear every active status effect on the caster and recover
    #: `soul_magnitude` battle points.
    PURGE = "purge"
    #: Absorb `soul_magnitude` percent of the damage the caster would
    #: take this round. A percentage, not a negation: see match.py.
    VEIL = "veil"
    #: Deal fixed damage to the opponent, ignoring their guard.
    RUIN = "ruin"
    #: Restore the caster's battle points to their value one round ago.
    REWIND = "rewind"


def _require_keys(raw: Mapping[str, Any], expected: frozenset[str], *, where: str) -> None:
    """Fail loudly on both missing and unexpected keys.

    Rejecting *unexpected* keys is what catches a rename. If the file says
    `technique_damage_boost` and the schema wants `technique_damage_bonus`,
    checking only for missing keys reports one problem; checking both reports
    the rename, which is the actual bug.
    """
    actual = frozenset(raw)
    missing = expected - actual
    unexpected = actual - expected
    if not missing and not unexpected:
        return

    # Report both halves in one message. A rename shows up as one missing key
    # and one unexpected key, and seeing only the missing half sends you
    # looking for a deleted field instead of a typo'd one.
    parts = []
    if missing:
        parts.append(f"missing key(s): {', '.join(sorted(missing))}")
    if unexpected:
        parts.append(f"unexpected key(s): {', '.join(sorted(unexpected))}")
    raise ValidationError(where, "; ".join(parts))


@dataclass(frozen=True, slots=True)
class Battlefield:
    """An arena. Its element decides who it favours; its soul mechanic is the
    depth layer a player unlocks by spending Soul."""

    id: str
    name: str
    element: Element
    flavour: str
    #: Extra damage multiplier for a fighter whose element matches the arena's.
    attunement_bonus: float
    #: Chance per round that a non-attuned fighter suffers the arena's hazard.
    hazard_chance: float
    #: The status effect the hazard inflicts, or None for a hazard-free arena.
    hazard_effect: str | None
    soul_cost: int
    soul_effect: SoulEffect
    soul_magnitude: int
    soul_name: str

    _KEYS = frozenset(
        {
            "id", "name", "element", "flavour", "attunement_bonus", "hazard_chance",
            "hazard_effect", "soul_cost", "soul_effect", "soul_magnitude", "soul_name",
        }
    )

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "Battlefield":
        where = f"battlefield[{raw.get('id', '?')}]"
        _require_keys(raw, cls._KEYS, where=where)
        hazard_effect = raw["hazard_effect"]
        if hazard_effect is not None:
            hazard_effect = validate_identifier(hazard_effect, field=f"{where}.hazard_effect")
        return cls(
            id=validate_identifier(raw["id"], field=f"{where}.id"),
            name=validate_text_field(raw["name"], field=f"{where}.name", max_length=48),
            element=validate_choice(raw["element"], field=f"{where}.element", allowed=Element),
            flavour=validate_text_field(raw["flavour"], field=f"{where}.flavour", max_length=200),
            attunement_bonus=validate_float(
                raw["attunement_bonus"], field=f"{where}.attunement_bonus",
                minimum=1.0, maximum=2.0,
            ),
            hazard_chance=validate_float(
                raw["hazard_chance"], field=f"{where}.hazard_chance", minimum=0.0, maximum=0.5
            ),
            hazard_effect=hazard_effect,
            soul_cost=validate_int(raw["soul_cost"], field=f"{where}.soul_cost", minimum=1, maximum=5),
            soul_effect=validate_choice(
                raw["soul_effect"], field=f"{where}.soul_effect", allowed=SoulEffect
            ),
            soul_magnitude=validate_int(
                raw["soul_magnitude"], field=f"{where}.soul_magnitude", minimum=0, maximum=100
            ),
            soul_name=validate_text_field(raw["soul_name"], field=f"{where}.soul_name", max_length=48),
        )


@dataclass(frozen=True, slots=True)
class Supremacy:
    """A fighter archetype. Carried forward from the original design, with the
    six archetypes and their power tiers intact."""

    id: str
    name: str
    abbreviation: str
    #: 1 (common) to 6 (rarest). Drives both draw weight and the stat budget.
    power_tier: int
    description: str
    strength: str
    weakness: str
    #: Percentage points of the stat budget nudged toward each stat, so an
    #: archetype reads differently even at the same tier. Must sum to zero.
    power_bias: int
    guard_bias: int
    focus_bias: int

    _KEYS = frozenset(
        {
            "id", "name", "abbreviation", "power_tier", "description", "strength",
            "weakness", "power_bias", "guard_bias", "focus_bias",
        }
    )

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "Supremacy":
        where = f"supremacy[{raw.get('id', '?')}]"
        _require_keys(raw, cls._KEYS, where=where)
        biases = {
            name: validate_int(raw[name], field=f"{where}.{name}", minimum=-6, maximum=6)
            for name in ("power_bias", "guard_bias", "focus_bias")
        }
        if sum(biases.values()) != 0:
            raise ValidationError(
                where, f"stat biases must sum to 0, got {sum(biases.values())}"
            )
        return cls(
            id=validate_identifier(raw["id"], field=f"{where}.id"),
            name=validate_text_field(raw["name"], field=f"{where}.name", max_length=48),
            abbreviation=validate_text_field(
                raw["abbreviation"], field=f"{where}.abbreviation", max_length=4
            ),
            power_tier=validate_int(
                raw["power_tier"], field=f"{where}.power_tier", minimum=1, maximum=6
            ),
            description=validate_text_field(
                raw["description"], field=f"{where}.description", max_length=200
            ),
            strength=validate_text_field(raw["strength"], field=f"{where}.strength", max_length=120),
            weakness=validate_text_field(raw["weakness"], field=f"{where}.weakness", max_length=120),
            **biases,
        )


@dataclass(frozen=True, slots=True)
class Rank:
    """A ladder tier.

    `damage_modifier` is the field whose backing database column never existed
    in the previous codebase, so rank had no effect on combat for the life of
    the project. It is now required content, range-checked, and covered by a
    test that asserts it actually changes damage.
    """

    id: str
    name: str
    points_required: int
    damage_modifier: float

    _KEYS = frozenset({"id", "name", "points_required", "damage_modifier"})

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "Rank":
        where = f"rank[{raw.get('id', '?')}]"
        _require_keys(raw, cls._KEYS, where=where)
        return cls(
            id=validate_identifier(raw["id"], field=f"{where}.id"),
            name=validate_text_field(raw["name"], field=f"{where}.name", max_length=48),
            points_required=validate_int(
                raw["points_required"], field=f"{where}.points_required",
                minimum=0, maximum=1_000_000,
            ),
            damage_modifier=validate_float(
                raw["damage_modifier"], field=f"{where}.damage_modifier",
                minimum=1.0, maximum=1.5,
            ),
        )


@dataclass(frozen=True, slots=True)
class TauntSet:
    """Flavour lines, keyed by the moment they fire.

    Carried over verbatim from the original game. The writing was the strongest
    asset in the previous repository and it costs nothing to keep.
    """

    lines: Mapping[str, tuple[str, ...]]

    REQUIRED_MOMENTS = frozenset({"hit", "miss", "combo", "soul", "victory", "defeat"})

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "TauntSet":
        where = "taunts"
        _require_keys(raw, cls.REQUIRED_MOMENTS, where=where)
        lines: dict[str, tuple[str, ...]] = {}
        for moment, entries in raw.items():
            if not isinstance(entries, list) or not entries:
                raise ValidationError(f"{where}.{moment}", "must be a non-empty list")
            lines[moment] = tuple(
                validate_text_field(line, field=f"{where}.{moment}[{i}]", max_length=160)
                for i, line in enumerate(entries)
            )
        return cls(lines=lines)


@dataclass(frozen=True, slots=True)
class GameContent:
    """Everything the engine needs, loaded once and immutable thereafter."""

    battlefields: tuple[Battlefield, ...]
    supremacies: tuple[Supremacy, ...]
    ranks: tuple[Rank, ...]
    taunts: TauntSet

    def battlefield(self, battlefield_id: str) -> Battlefield:
        for arena in self.battlefields:
            if arena.id == battlefield_id:
                return arena
        raise KeyError(f"unknown battlefield: {battlefield_id!r}")

    def supremacy(self, supremacy_id: str) -> Supremacy:
        for archetype in self.supremacies:
            if archetype.id == supremacy_id:
                return archetype
        raise KeyError(f"unknown supremacy: {supremacy_id!r}")

    def rank_for(self, points: int) -> Rank:
        """The highest rank whose threshold `points` has reached.

        `ranks` is sorted ascending at load time, so the last match wins.
        """
        earned = self.ranks[0]
        for rank in self.ranks:
            if points >= rank.points_required:
                earned = rank
            else:
                break
        return earned
