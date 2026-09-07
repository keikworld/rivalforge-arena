"""Turning game state into Telegram messages.

Two rules, and everything here follows from them.

**One escaping choke point.** Almost every message the bot sends is a single
MarkdownV2 fenced block. Inside one, exactly two characters are syntax, so the
escape surface is two characters instead of sixteen -- and the game is made of
aligned bars and columns, which want monospace anyway. `code_block` is the only
function that produces one, so there is one place to audit.

**One sanitising choke point.** Attacker-controlled text -- NFT names, above
all -- is cleaned where it *enters* the bot (`fighters.py`), not at each place
it is drawn. Cleaning at the render site means every new render site is a new
chance to forget.

Every function here is pure. No I/O, no clock, no network -- the same property
that makes `cli/render.py` testable, for the same reason.
"""

from __future__ import annotations

from typing import Final, Iterable, Mapping, Sequence

from ..cli import render as text_render
from ..content.schema import GameContent, Stance
from ..engine import balance
from ..engine.fighter import Fighter
from ..engine.match import Event, MatchView, Outcome, Side
from ..engine.rng import RNG
from .security import escape_code, escape_markdown

__all__ = [
    "code_block",
    "plain",
    "board_text",
    "round_text",
    "outcome_text",
    "fighter_line",
    "roster_text",
    "stance_keyboard",
    "menu_keyboard",
    "pick_keyboard",
    "HELP_TEXT",
]

#: Telegram's message ceiling with room left for the fence and escapes.
_BODY_BUDGET: Final = 3_600


def code_block(body: str) -> str:
    """Wrap plain text in a MarkdownV2 fenced block.

    The escaping is the security control: without it, a backtick inside an NFT
    name closes the block early and everything after it is parsed as markup.
    """
    trimmed = body if len(body) <= _BODY_BUDGET else body[: _BODY_BUDGET - 1] + "…"
    return f"```\n{escape_code(trimmed)}\n```"


def plain(text: str) -> str:
    """MarkdownV2-escaped free text, for the few messages that are not a block."""
    return escape_markdown(text)


def fighter_line(fighter: Fighter) -> str:
    """One line of fighter identity. The mint is truncated, as everywhere else."""
    return text_render.render_fighter(fighter)


def board_text(view: MatchView, *, header: str = "") -> str:
    """The state of play from one side, as the body of a block."""
    parts = []
    if header:
        parts.append(header)
    parts.append(f"{view.arena.name}  ({view.arena.element.value})")
    parts.append(text_render.render_board(view, balance.MAX_SOULS))
    if view.can_spend_soul:
        parts.append(f"  soul ready: {view.arena.soul_name} ({view.arena.soul_cost})")
    return "\n".join(parts)


def round_text(
    events: Iterable[Event],
    names: Mapping[Side, str],
    content: GameContent,
    rng: RNG,
) -> str:
    """One round's events, as the body of a block."""
    lines = text_render.render_events(events, dict(names), content, rng)
    return "\n".join(line for line in lines if line.strip())


def outcome_text(
    outcome: Outcome,
    names: Mapping[Side, str],
    content: GameContent,
    rng: RNG,
    viewer: Side | None,
) -> str:
    """The closing lines, as the body of a block."""
    return text_render.render_outcome(outcome, dict(names), content, rng, viewer).strip()


def roster_text(fighters: Sequence[tuple[str, Fighter]]) -> str:
    """The wallet's playable NFTs, numbered so a button can name one."""
    if not fighters:
        return (
            "This wallet holds no NFTs that can fight.\n"
            "Anything you hold works -- no special collection needed."
        )
    lines = ["Your fighters:", ""]
    for index, (_, fighter) in enumerate(fighters, start=1):
        lines.append(f"{index:>2}. {fighter_line(fighter)}")
    lines.append("")
    lines.append("Tap one to make it your fighter.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Keyboards
# --------------------------------------------------------------------------

#: The action codes that travel in signed callback data. Two characters each,
#: because the 64-byte budget is spent on the signature.
ACTION_STANCE: Final = "st"
ACTION_SOUL: Final = "sl"
ACTION_PLAY: Final = "pl"
ACTION_PICK: Final = "pk"
ACTION_ROSTER: Final = "ro"
ACTION_QUIT: Final = "qt"

_STANCE_LABEL: Final = {
    Stance.STRIKE: "Strike",
    Stance.GUARD: "Guard",
    Stance.FOCUS: "Focus",
}


def stance_keyboard(sign, user_id: int, *, soul_ready: bool, soul_name: str, armed: bool):
    """The three stances, plus a soul toggle when one is affordable.

    `sign` is the callback signer's `sign` method. Every button's payload is
    signed and bound to `user_id`, so a button lifted from someone else's chat
    does nothing in this one.
    """
    row = [
        {"text": _STANCE_LABEL[stance], "callback_data": sign(ACTION_STANCE, stance.value, user_id)}
        for stance in (Stance.STRIKE, Stance.GUARD, Stance.FOCUS)
    ]
    rows = [row]
    if soul_ready:
        label = f"✦ {soul_name}" + (" (armed)" if armed else "")
        rows.append([{"text": label, "callback_data": sign(ACTION_SOUL, "toggle", user_id)}])
    rows.append([{"text": "Forfeit", "callback_data": sign(ACTION_QUIT, "match", user_id)}])
    return rows


def menu_keyboard(sign, user_id: int, *, has_wallet: bool):
    """What to offer when no match is running."""
    rows = [[{"text": "▶ Play", "callback_data": sign(ACTION_PLAY, "start", user_id)}]]
    if has_wallet:
        rows.append(
            [{"text": "Your NFTs", "callback_data": sign(ACTION_ROSTER, "list", user_id)}]
        )
    return rows


def pick_keyboard(sign, user_id: int, count: int):
    """Numbered buttons for a roster, three to a row."""
    buttons = [
        {"text": str(i), "callback_data": sign(ACTION_PICK, str(i), user_id)}
        for i in range(1, count + 1)
    ]
    return [buttons[i : i + 5] for i in range(0, len(buttons), 5)]


HELP_TEXT: Final = """RivalForge -- sixty-second NFT duels.

/play        start a duel against an agent
/connect     link a Solana wallet (read-only)
/roster      the NFTs you can fight with
/whoami      which wallet this chat is using
/disconnect  end the session and forget you
/help        this

You do not need a wallet to play. Connecting one lets you
fight as an NFT you actually own.

This bot never asks you to sign a transaction, and cannot
move anything out of your wallet. It asks you to sign a
plain text message, which is the whole of what it can do.
"""
