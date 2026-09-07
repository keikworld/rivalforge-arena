"""Turning engine events into something a person can read.

Kept apart from the engine on purpose: the engine emits `Event` objects and
never prints. That separation is what lets the same match drive a terminal, a
Telegram message, a replay viewer or a test, and it is why the AI-vs-AI mode
needed no second code path.

Everything here is a pure string function -- no printing, no I/O -- so the
renderer is as testable as the engine.
"""

from __future__ import annotations

from typing import Final, Iterable

from ..content.schema import Battlefield, GameContent, Stance
from ..engine.balance import STARTING_BP
from ..engine.fighter import Fighter
from ..engine.match import Event, EventKind, MatchView, Outcome, Side
from ..engine.rng import RNG

__all__ = ["bp_bar", "render_events", "render_board", "render_fighter", "render_outcome"]

BAR_WIDTH: Final = 24

#: Plain ASCII. A terminal that cannot render a block character should still
#: show a readable bar, and the same strings have to survive being pasted into
#: a Telegram message later.
_FULL: Final = "#"
_EMPTY: Final = "."

_STANCE_GLYPH: Final = {
    Stance.STRIKE: ">>",
    Stance.GUARD: "[]",
    Stance.FOCUS: "()",
}


def bp_bar(current: int, maximum: int = STARTING_BP, width: int = BAR_WIDTH) -> str:
    """A battle-point bar: ``[########........]  64/100``."""
    current = max(0, min(maximum, current))
    filled = round(width * current / maximum) if maximum else 0
    # A living fighter always shows at least one segment, so "nearly dead" and
    # "dead" never look the same.
    if current > 0:
        filled = max(1, filled)
    return f"[{_FULL * filled}{_EMPTY * (width - filled)}] {current:>3}/{maximum}"


def render_fighter(fighter: Fighter) -> str:
    """One line of fighter identity, safe to log: the mint is truncated."""
    return (
        f"{fighter.name}  {fighter.supremacy.abbreviation}/{fighter.element.value}  "
        f"PWR {fighter.power}  GRD {fighter.guard}  FOC {fighter.focus}  "
        f"({fighter.short_mint})"
    )


def render_board(view: MatchView, souls_max: int) -> str:
    """The state of play, from one side's point of view."""
    lines = [
        f"  {view.you.name:<16} {bp_bar(view.your_bp)}  "
        f"soul {view.your_souls}/{souls_max}"
        + (f"  [{', '.join(sorted(view.your_statuses))}]" if view.your_statuses else ""),
        f"  {view.opponent.name:<16} {bp_bar(view.opponent_bp)}  "
        f"soul {view.opponent_souls}/{souls_max}"
        + (
            f"  [{', '.join(sorted(view.opponent_statuses))}]"
            if view.opponent_statuses
            else ""
        ),
    ]
    if view.opponent_history:
        recent = " ".join(_STANCE_GLYPH[s] for s in view.opponent_history[-6:])
        lines.append(f"  they played:     {recent}")
    return "\n".join(lines)


def render_arena(arena: Battlefield) -> str:
    return (
        f"{arena.name}  ({arena.element.value})\n"
        f"  {arena.flavour}\n"
        f"  {arena.soul_name} -- costs {arena.soul_cost} soul"
    )


def render_events(
    events: Iterable[Event],
    names: dict[Side, str],
    content: GameContent,
    rng: RNG,
) -> list[str]:
    """Turn one round's events into display lines.

    `rng` picks the flavour line. It is passed in rather than taken from the
    match so that narration never perturbs the match's own stream -- the same
    match must replay identically whether or not anyone was watching.
    """
    lines: list[str] = []
    taunts = content.taunts.lines

    for event in events:
        who = names[event.side] if event.side else ""
        if event.kind is EventKind.ROUND_START:
            lines.append(f"\n-- round {event.amount} --")
        elif event.kind is EventKind.STANCE:
            # Never let a rendering surprise take the match down. The engine
            # validates stances, but a renderer that raises on an unfamiliar
            # detail string turns a cosmetic problem into a crash.
            try:
                stance = Stance(event.detail)
            except ValueError:
                lines.append(f"  {who} {event.detail}")
            else:
                lines.append(f"  {who} {_STANCE_GLYPH[stance]} {stance.value}")
        elif event.kind is EventKind.DAMAGE:
            lines.append(f"  {who} takes {event.amount}.  {rng.choice(taunts['hit'])}")
        elif event.kind is EventKind.BLOCKED:
            lines.append(f"  {who} absorbs {event.amount} with {event.detail}.")
        elif event.kind is EventKind.SOUL_SPENT:
            if "denied" in event.detail:
                lines.append(f"  {who} reaches for a soul and finds none.")
            else:
                lines.append(f"  {who} spends soul: {event.detail}!  {rng.choice(taunts['soul'])}")
        elif event.kind is EventKind.SOUL_GAINED:
            lines.append(f"  {who} gathers a soul.")
        elif event.kind is EventKind.HAZARD:
            lines.append(f"  The arena turns on {who}: {event.detail}.")
        elif event.kind is EventKind.STATUS_DAMAGE:
            lines.append(f"  {who} suffers {event.amount} from lingering harm.")
        elif event.kind is EventKind.KO:
            lines.append(f"  {who} goes down.")
        elif event.kind is EventKind.MATCH_END:
            pass  # rendered by render_outcome, which knows the viewer
    return lines


def render_outcome(
    outcome: Outcome, names: dict[Side, str], content: GameContent, rng: RNG,
    viewer: Side | None = None,
) -> str:
    """The closing lines. `viewer` picks victory or defeat flavour."""
    taunts = content.taunts.lines
    header = "\n" + "=" * 46
    if outcome.winner is None:
        return (
            f"{header}\n  DRAW after {outcome.rounds} rounds ({outcome.reason}).\n"
            + "=" * 46
        )

    winner = names[outcome.winner]
    body = f"{header}\n  {winner} wins in {outcome.rounds} rounds ({outcome.reason})."
    if viewer is not None:
        moment = "victory" if outcome.winner is viewer else "defeat"
        body += f"\n  {rng.choice(taunts[moment])}"
    return body + "\n" + "=" * 46
