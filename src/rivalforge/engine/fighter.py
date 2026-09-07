"""Deriving a fighter from an NFT mint address.

This is the idea the whole product rests on: **any NFT, from any collection,
is playable the moment its owner connects a wallet.** No custom metadata, no
minting, no per-collection integration.

A fighter is a pure function of its mint address. Same address, same fighter,
on every machine, forever. That gives three things at once:

* a use for NFTs whose collections have gone quiet, which was the goal;
* zero onboarding cost per collection, which is the growth story;
* no fighter database to keep, migrate, or have stolen.

The derivation is a hash, not a secret. Anyone can compute their own fighter
offline and check ours matches -- that is a feature. Nothing here is a
security boundary: *ownership* of the mint is verified separately, on-chain,
and this module makes no claim about it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from ..content.schema import Element, GameContent, Supremacy
from ..security.validation import (
    ValidationError,
    sanitize_display_name,
    validate_mint_address,
)
from . import balance
from .rng import RNG

__all__ = ["Fighter", "derive_fighter", "starter_fighter"]

#: Domain separators, so the supremacy draw and the element draw are
#: independent. Without these, a fighter's element would correlate with its
#: archetype and half the roster would never appear.
_SUPREMACY_LABEL: Final = "supremacy"
_ELEMENT_LABEL: Final = "element"
_STATS_LABEL: Final = "stats"


@dataclass(frozen=True, slots=True)
class Fighter:
    """A combat-ready fighter. Immutable; per-match state lives in `Match`."""

    mint: str
    name: str
    supremacy: Supremacy
    element: Element
    power: int
    guard: int
    focus: int
    #: Ladder points carried by the *player*, not the NFT. Zero for a fresh
    #: fighter; the caller supplies a stored value for a returning player.
    points: int = 0

    def __post_init__(self) -> None:
        total = self.power + self.guard + self.focus
        if total != balance.STAT_BUDGET:
            raise ValueError(
                f"stats must total {balance.STAT_BUDGET}, got {total} "
                f"(power={self.power}, guard={self.guard}, focus={self.focus})"
            )
        for label, value in (("power", self.power), ("guard", self.guard), ("focus", self.focus)):
            if not (balance.STAT_MINIMUM <= value <= balance.STAT_MAXIMUM):
                raise ValueError(
                    f"{label} must be between {balance.STAT_MINIMUM} and "
                    f"{balance.STAT_MAXIMUM}, got {value}"
                )

    @property
    def short_mint(self) -> str:
        """A truncated mint for display and logging."""
        if len(self.mint) <= 11:
            return self.mint
        return f"{self.mint[:4]}...{self.mint[-4:]}"

    def describe(self) -> str:
        return (
            f"{self.name}  [{self.supremacy.abbreviation}/{self.element.value}]  "
            f"PWR {self.power}  GRD {self.guard}  FOC {self.focus}"
        )


def _draw_supremacy(rng: RNG, content: GameContent) -> Supremacy:
    """Draw an archetype, weighted so the strong ones stay rare."""
    ordered = sorted(content.supremacies, key=lambda s: s.power_tier)
    weights = [balance.SUPREMACY_TIER_WEIGHTS[s.power_tier - 1] for s in ordered]
    return rng.weighted_choice(ordered, weights)


def _draw_stats(rng: RNG, supremacy: Supremacy) -> tuple[int, int, int]:
    """Split the stat budget three ways, nudged by the archetype's biases.

    Every fighter gets the same total, so the mint hash decides a fighter's
    *shape*, never its strength. A lucky hash produces an interesting fighter,
    not a stronger one. Rarity lives in the archetype draw, which is visible,
    rather than in a hidden stat roll, which would be pay-to-win by accident.
    """
    stats = [balance.STAT_MINIMUM, balance.STAT_MINIMUM, balance.STAT_MINIMUM]
    biases = (supremacy.power_bias, supremacy.guard_bias, supremacy.focus_bias)

    remaining = balance.STAT_BUDGET - sum(stats)
    if remaining < 0:  # pragma: no cover - guarded by the balance constants
        raise ValueError("STAT_BUDGET is below the minimum for three stats")

    # Apply archetype bias first, clamped so it can never break the bounds.
    for index, bias in enumerate(biases):
        if bias > 0:
            step = min(bias, remaining, balance.STAT_MAXIMUM - stats[index])
            stats[index] += step
            remaining -= step

    # Distribute what is left one point at a time, choosing only among stats
    # that still have headroom. One point at a time is slower than a single
    # multinomial draw and much easier to prove correct.
    while remaining > 0:
        candidates = [i for i in range(3) if stats[i] < balance.STAT_MAXIMUM]
        if not candidates:  # pragma: no cover - impossible with current budget
            raise ValueError("stat budget exceeds what three capped stats can hold")
        weights = []
        for i in candidates:
            # A negative bias makes a stat less likely to receive points, but
            # never impossible: a floor of 1 keeps every shape reachable.
            weights.append(max(1, 4 + biases[i]))
        chosen = rng.weighted_choice(candidates, weights)
        stats[chosen] += 1
        remaining -= 1

    return stats[0], stats[1], stats[2]


def derive_fighter(
    mint: str, content: GameContent, *, name: str | None = None, points: int = 0
) -> Fighter:
    """Derive the fighter for `mint`.

    Args:
        mint: A base58 Solana mint address. Structurally validated here;
            ownership is *not* checked and must be verified separately.
        content: Loaded game content.
        name: Optional player-supplied display name. Sanitized. Falls back to
            the archetype name plus a short mint, which is always safe.
        points: Ladder points to attach, from the player's stored record.

    Raises:
        ValidationError: if the mint or the name is malformed.
    """
    validate_mint_address(mint)
    if not isinstance(points, int) or isinstance(points, bool) or points < 0:
        raise ValidationError("points", f"must be a non-negative integer, got {points!r}")

    root = RNG.from_bytes(mint.encode("ascii"))
    supremacy = _draw_supremacy(root.fork(_SUPREMACY_LABEL), content)
    element = root.fork(_ELEMENT_LABEL).choice(tuple(Element))
    power, guard, focus = _draw_stats(root.fork(_STATS_LABEL), supremacy)

    if name is None:
        display = f"{supremacy.abbreviation} {mint[:4]}"
    else:
        display = sanitize_display_name(name)

    return Fighter(
        mint=mint,
        name=display,
        supremacy=supremacy,
        element=element,
        power=power,
        guard=guard,
        focus=focus,
        points=points,
    )


def starter_fighter(content: GameContent, *, name: str = "Recruit") -> Fighter:
    """A fixed, wallet-free fighter so a new player can fight immediately.

    Requiring a wallet before the first match is the single largest drop-off in
    this genre. The starter is deliberately average -- a balanced Keiknight
    with an even spread -- so it teaches the game without being the best pick.
    """
    supremacy = content.supremacy("keiknight_warrior")
    return Fighter(
        mint="1" * 32,  # a valid, decodable, obviously-not-real address
        name=sanitize_display_name(name),
        supremacy=supremacy,
        element=Element.WIND,
        power=10,
        guard=10,
        focus=10,
    )
