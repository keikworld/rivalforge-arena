"""Update handling: the whole of what the bot does, with nothing that does I/O.

`handle()` takes a raw Telegram update and returns a list of *actions* --
"send this text", "edit that message", "acknowledge this button". Nothing here
opens a socket. The loop in `bot.py` is what performs them.

That split is the reason this file can be tested exhaustively. Every attack in
`security.py` -- a forged callback, a group chat, a flood, an NFT named after a
phishing link -- is a dictionary passed to `handle()` and an assertion about
what comes back. No network, no fixtures, no waiting.

## The order of checks

Every update goes through the same gate, in this order, and the order is the
control:

1.  **Shape.** Is this a mapping with a user id in it? Everything after this
    assumes the answer is yes.
2.  **Not a bot.** Two bots replying to each other is an infinite loop that
    bills someone.
3.  **Rate limit.** Before any work -- the expensive parts (an RPC call, a
    database write) are exactly what a flood targets.
4.  **Chat type**, for anything sensitive. A challenge posted in a group is a
    challenge every member can read.
5.  **Authenticity**, for callbacks. The payload is signed and bound to the
    user, so a button lifted from another chat does nothing here.
6.  Only then, the command itself.

## What a player can and cannot do to their own account

They can connect a wallet, play, and disconnect. They cannot make the bot sign
anything, cannot reach another player's session, and cannot get the bot to
repeat text back to them without it passing through the escaping in
`render.py` first.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Final, Mapping, Sequence

from ..agents.builtin import build_agent
from ..auth.challenge import AuthError, build_message
from ..auth.service import OwnershipRequired
from ..auth.store import RateLimitExceeded
from ..cli.wiring import Application
from ..content.schema import Stance
from ..engine.fighter import Fighter, derive_fighter, starter_fighter
from ..engine.match import Decision, Match, Side
from ..engine.rng import RNG, new_seed
from ..plugins.ports import OwnedNFT
from ..security.redaction import short_address
from ..security.validation import ValidationError, validate_mint_address
from . import render
from .security import (
    Callback,
    CallbackError,
    CallbackSigner,
    RateLimited,
    RateLimiter,
    WrongChatType,
    clean_text,
    require_private_chat,
    validate_chat_id,
    validate_user_id,
)
from .state import StateStore, UserState

logger = logging.getLogger(__name__)

__all__ = [
    "Action",
    "SendMessage",
    "EditMessage",
    "AnswerCallback",
    "BotHandlers",
]

#: Longest message text we will even look at. Telegram's own cap is 4096; this
#: is the ceiling on what we parse, so a pathological update is discarded
#: before it reaches a regular expression.
MAX_TEXT: Final = 4_096

#: Roster size shown in a chat. More than this is a wall of text and a keyboard
#: that does not fit on a phone.
ROSTER_LIMIT: Final = 20

#: Who you fight when you have not chosen otherwise.
DEFAULT_OPPONENT: Final = "adaptive"


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SendMessage:
    """Send a new message to a chat."""

    chat_id: int
    text: str
    keyboard: Sequence[Sequence[Mapping[str, str]]] | None = None


@dataclass(frozen=True, slots=True)
class EditMessage:
    """Replace the text of an existing message, so a match updates in place."""

    chat_id: int
    message_id: int
    text: str
    keyboard: Sequence[Sequence[Mapping[str, str]]] | None = None


@dataclass(frozen=True, slots=True)
class AnswerCallback:
    """Acknowledge a button press. Always sent, including on refusal."""

    callback_id: str
    text: str = ""
    alert: bool = False


Action = SendMessage | EditMessage | AnswerCallback


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


class BotHandlers:
    """Every command and button the bot understands.

    Holds no connection of its own: the wallet service, the content and the
    clock all arrive from the composition root, exactly as they do for the CLI.
    """

    def __init__(
        self,
        app: Application,
        *,
        signer: CallbackSigner | None = None,
        limiter: RateLimiter | None = None,
        states: StateStore | None = None,
        opponent: str = DEFAULT_OPPONENT,
    ) -> None:
        self._app = app
        # `is None`, not `or`: `RateLimiter` and `StateStore` both define
        # `__len__`, so an empty one is falsy and `limiter or RateLimiter()`
        # silently threw away the caller's instance and built a fresh one --
        # which is a rate limiter that resets itself, i.e. no rate limiter.
        self._signer = CallbackSigner() if signer is None else signer
        self._limiter = RateLimiter() if limiter is None else limiter
        self._states = StateStore() if states is None else states
        self._opponent = opponent

    # -- entry point ------------------------------------------------------

    def handle(self, update: Mapping[str, Any]) -> list[Action]:
        """Turn one update into the actions it deserves.

        Never raises. An update that cannot be understood produces no actions:
        a bot that dies on a malformed update is a bot that anyone can stop.
        """
        if not isinstance(update, Mapping):
            return []
        try:
            if isinstance(update.get("callback_query"), Mapping):
                return self._on_callback(update["callback_query"])
            if isinstance(update.get("message"), Mapping):
                return self._on_message(update["message"])
        except Exception:
            # Logged with the traceback, answered with nothing that describes
            # it. An internal error message is a map of the internals.
            logger.exception("unhandled error while processing an update")
            return []
        return []

    # -- messages ---------------------------------------------------------

    def _on_message(self, message: Mapping[str, Any]) -> list[Action]:
        sender = message.get("from")
        if not isinstance(sender, Mapping) or sender.get("is_bot"):
            # No handler for another bot. Two bots replying to each other is a
            # loop that nobody is watching.
            return []
        try:
            user_id = validate_user_id(sender.get("id"))
        except ValidationError:
            return []

        chat = message.get("chat")
        if not isinstance(chat, Mapping):
            return []
        try:
            chat_id = validate_chat_id(chat.get("id"))
        except ValidationError:
            return []

        try:
            self._limiter.check(user_id)
        except RateLimited:
            # Dropped in silence. Answering a flood is amplifying it, and the
            # sender already knows what they are doing.
            logger.info("rate limited an update from user %d", user_id)
            return []

        raw = message.get("text")
        if not isinstance(raw, str) or not raw.strip():
            return [SendMessage(chat_id, render.plain("Send /help to see what I can do."))]
        if len(raw) > MAX_TEXT:
            return [SendMessage(chat_id, render.plain("That message is too long for me."))]

        command, _, argument = raw.strip().partition(" ")
        # `/play@RivalForgeBot` in a group carries the bot's name. Strip it.
        command = command.split("@", 1)[0].lower()
        argument = argument.strip()

        state = self._states.get(user_id)
        handler = _COMMANDS.get(command)
        if handler is None:
            return [
                SendMessage(
                    chat_id,
                    render.plain("I did not understand that. Send /help."),
                    render.menu_keyboard(
                        self._signer.sign, user_id, has_wallet=state.session_token is not None
                    ),
                )
            ]
        return handler(self, chat, chat_id, state, argument)

    # -- callbacks --------------------------------------------------------

    def _on_callback(self, query: Mapping[str, Any]) -> list[Action]:
        callback_id = query.get("id")
        if not isinstance(callback_id, str) or not callback_id:
            return []

        sender = query.get("from")
        if not isinstance(sender, Mapping) or sender.get("is_bot"):
            return []
        try:
            user_id = validate_user_id(sender.get("id"))
        except ValidationError:
            return []

        try:
            self._limiter.check(user_id)
        except RateLimited:
            return [AnswerCallback(callback_id, "Slow down for a moment.")]

        message = query.get("message")
        if not isinstance(message, Mapping):
            return [AnswerCallback(callback_id, "That message is too old to use.")]
        chat = message.get("chat")
        try:
            chat_id = validate_chat_id((chat or {}).get("id"))
            message_id = validate_chat_id(message.get("message_id"), field="message_id")
        except ValidationError:
            return [AnswerCallback(callback_id, "That message is too old to use.")]

        try:
            callback: Callback = self._signer.verify(query.get("data"), user_id)
        except CallbackError as exc:
            # One message for every failure. A player who forwarded a button to
            # a friend and a player probing the format get the same answer.
            logger.info("rejected a callback from user %d: %s", user_id, exc)
            return [AnswerCallback(callback_id, "That button is not for you.", alert=True)]

        state = self._states.get(user_id)
        action = _CALLBACKS.get(callback.action)
        if action is None:
            return [AnswerCallback(callback_id, "That button does nothing any more.")]
        return action(self, callback_id, chat_id, message_id, state, callback.argument)

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _cmd_start(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        body = (
            "RivalForge\n"
            "sixty-second NFT duels\n\n"
            "Pick a stance each round. Strike beats Focus, Guard beats\n"
            "Strike, Focus beats Guard -- and Focus is the only way to\n"
            "gather Soul.\n\n"
            "Play now, or connect a wallet to fight as an NFT you own."
        )
        return [
            SendMessage(
                chat_id,
                render.code_block(body),
                render.menu_keyboard(
                    self._signer.sign, state.user_id, has_wallet=state.session_token is not None
                ),
            )
        ]

    def _cmd_help(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        return [SendMessage(chat_id, render.code_block(render.HELP_TEXT))]

    def _cmd_play(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        return self._begin_match(chat_id, state)

    def _cmd_connect(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        """Issue a challenge to sign. Private chats only.

        The message is plain text and always will be. This bot has no code path
        that builds a transaction, and `challenge.py` refuses to issue anything
        transaction-shaped -- so "sign this to connect" cannot become "sign this
        to drain your wallet", even by mistake.
        """
        try:
            require_private_chat(chat)
        except WrongChatType as exc:
            return [SendMessage(chat_id, render.plain(str(exc)))]

        if not argument:
            return [
                SendMessage(
                    chat_id,
                    render.code_block(
                        "Send your Solana address:\n\n"
                        "  /connect <your wallet address>\n\n"
                        "I will reply with a short text message to sign in\n"
                        "your wallet. It is a message, never a transaction --\n"
                        "signing it cannot move anything."
                    ),
                )
            ]

        try:
            wallet = validate_mint_address(argument.split()[0], field="wallet")
        except (ValidationError, IndexError):
            return [
                SendMessage(
                    chat_id,
                    render.plain("That is not a Solana address. Check it and try again."),
                )
            ]

        try:
            challenge = self._app.wallets.begin(wallet)
        except RateLimitExceeded:
            return [
                SendMessage(
                    chat_id,
                    render.plain("Too many connection attempts for that wallet. Wait a minute."),
                )
            ]
        except Exception:
            logger.exception("could not issue a challenge")
            return [SendMessage(chat_id, render.plain("I could not do that right now."))]

        state.pending_nonce = challenge.nonce
        body = (
            "Sign this message in your wallet, then send me the\n"
            "signature with:\n\n"
            "  /signed <signature>\n\n"
            "----- message to sign -----\n"
            f"{build_message(challenge)}\n"
            "---------------------------\n\n"
            "This is a plain message. It is not a transaction and\n"
            "signing it cannot move anything out of your wallet."
        )
        return [SendMessage(chat_id, render.code_block(body))]

    def _cmd_signed(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        try:
            require_private_chat(chat)
        except WrongChatType as exc:
            return [SendMessage(chat_id, render.plain(str(exc)))]

        nonce = state.pending_nonce
        if nonce is None:
            return [SendMessage(chat_id, render.plain("Start with /connect first."))]
        if not argument:
            return [SendMessage(chat_id, render.plain("Send the signature: /signed <signature>"))]

        # Consumed whether or not it verifies. A challenge that survives a
        # failed attempt is a challenge someone can keep guessing at.
        state.pending_nonce = None

        try:
            connected = self._app.wallets.complete(nonce, argument.split()[0])
        except AuthError:
            return [
                SendMessage(
                    chat_id,
                    render.plain("That signature did not check out. Run /connect again."),
                )
            ]
        except Exception:
            logger.exception("could not complete a connection")
            return [SendMessage(chat_id, render.plain("I could not do that right now."))]

        state.session_token = connected.token
        state.wallet = connected.wallet
        state.chosen_mint = None
        state.chosen_name = None
        body = (
            f"Connected: {connected.short_wallet}\n\n"
            "I can read which NFTs you hold. I cannot move them,\n"
            "and I never will be able to -- there is no code in me\n"
            "that builds a transaction.\n\n"
            "/roster to pick a fighter."
        )
        return [
            SendMessage(
                chat_id,
                render.code_block(body),
                render.menu_keyboard(self._signer.sign, state.user_id, has_wallet=True),
            )
        ]

    def _cmd_whoami(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        if state.session_token is None:
            return [SendMessage(chat_id, render.plain("No wallet connected. Send /connect."))]
        lines = [f"wallet   {short_address(state.wallet or '')}"]
        if state.chosen_mint:
            lines.append(f"fighter  {short_address(state.chosen_mint)}")
        else:
            lines.append("fighter  none chosen (/roster)")
        return [SendMessage(chat_id, render.code_block("\n".join(lines)))]

    def _cmd_disconnect(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        """End the session and forget the conversation entirely."""
        token = state.session_token
        if token is not None:
            try:
                self._app.wallets.disconnect(token)
            except Exception:
                logger.exception("could not revoke a session")
        self._states.forget(state.user_id)
        return [
            SendMessage(
                chat_id,
                render.plain("Disconnected. I have forgotten your session."),
            )
        ]

    def _cmd_roster(self, chat, chat_id: int, state: UserState, argument: str) -> list[Action]:
        try:
            require_private_chat(chat)
        except WrongChatType as exc:
            return [SendMessage(chat_id, render.plain(str(exc)))]
        return self._show_roster(chat_id, state)

    # ------------------------------------------------------------------
    # Shared flows
    # ------------------------------------------------------------------

    def _show_roster(self, chat_id: int, state: UserState) -> list[Action]:
        if state.session_token is None:
            return [SendMessage(chat_id, render.plain("Connect a wallet first: /connect"))]
        try:
            owned = self._app.wallets.roster(state.session_token, limit=ROSTER_LIMIT)
        except AuthError:
            state.session_token = None
            state.wallet = None
            return [SendMessage(chat_id, render.plain("Your session expired. Send /connect."))]
        except Exception:
            # An outage is not "you have no NFTs". Telling a player their
            # holdings are gone because an RPC endpoint is down is the worst
            # possible way to be wrong.
            logger.warning("roster unavailable", exc_info=True)
            return [
                SendMessage(
                    chat_id,
                    render.plain("I could not read your wallet just now. Try again shortly."),
                )
            ]

        fighters = self._fighters_for(owned)
        # Mint *and* the cleaned name. Picking "Pilot" and being handed a
        # fighter called something else reads as the bot losing your choice.
        state.match_context["roster"] = [(mint, f.name) for mint, f in fighters]
        return [
            SendMessage(
                chat_id,
                render.code_block(render.roster_text(fighters)),
                render.pick_keyboard(self._signer.sign, state.user_id, len(fighters))
                if fighters
                else None,
            )
        ]

    def _fighters_for(self, owned: Sequence[OwnedNFT]) -> list[tuple[str, Fighter]]:
        """Build fighters from a wallet's holdings.

        **This is the trust boundary for NFT metadata.** `nft.name` is written
        by whoever minted the token; `clean_text` is applied here, once, so
        every render site downstream is working with text that has already had
        its control characters, bidi overrides and excess length removed.
        """
        fighters: list[tuple[str, Fighter]] = []
        for nft in owned:
            try:
                mint = validate_mint_address(nft.mint, field="mint")
                fighter = derive_fighter(mint, self._app.content, name=clean_text(nft.name))
            except ValidationError:
                # One malformed asset must not cost a player the other forty.
                logger.info("skipping an unusable asset in a roster")
                continue
            fighters.append((mint, fighter))
        return fighters

    def _begin_match(
        self, chat_id: int, state: UserState, *, message_id: int | None = None
    ) -> list[Action]:
        """Start a duel and draw the first board."""
        seed = new_seed()
        rng = RNG(seed)
        content = self._app.content
        arena = rng.fork("arena").choice(content.battlefields)

        you = self._player_fighter(state)
        rival_seed = rng.fork("rival")
        rival = derive_fighter(
            _synthetic_mint(rival_seed), content, name="Rival"
        )

        match = Match.create(you, rival, arena, content, seed=seed)
        state.match = match
        state.soul_armed = False
        state.match_context = {
            "names": {Side.A: you.name, Side.B: rival.name},
            "narrator": RNG(seed).fork("narration"),
            "agent": build_agent(self._opponent, RNG(seed).fork("opponent")),
            "roster": state.match_context.get("roster", []),
        }

        body = "\n".join(
            [
                f"A  {render.fighter_line(you)}",
                f"B  {render.fighter_line(rival)}",
                "",
                render.board_text(match.view(Side.A)),
            ]
        )
        keyboard = self._match_keyboard(state)
        text = render.code_block(body)
        if message_id is None:
            return [SendMessage(chat_id, text, keyboard)]
        return [EditMessage(chat_id, message_id, text, keyboard)]

    def _player_fighter(self, state: UserState) -> Fighter:
        """The player's fighter, re-checking ownership every single match.

        Never a cached grant. An NFT can be sold between one match and the
        next, and a fighter that keeps working after the token is gone is a
        fighter someone rents out.
        """
        if state.session_token and state.chosen_mint:
            try:
                return self._app.wallets.fighter_for(
                    state.session_token, state.chosen_mint, name=state.chosen_name
                )
            except (AuthError, OwnershipRequired, ValidationError):
                logger.info("falling back to the starter fighter; ownership not confirmed")
                state.chosen_mint = None
                state.chosen_name = None
            except Exception:
                logger.exception("ownership check failed")
                state.chosen_mint = None
                state.chosen_name = None
        return starter_fighter(self._app.content, name="Recruit")

    def _match_keyboard(self, state: UserState):
        match = state.match
        view = match.view(Side.A)
        return render.stance_keyboard(
            self._signer.sign,
            state.user_id,
            soul_ready=view.can_spend_soul,
            soul_name=view.arena.soul_name,
            armed=state.soul_armed,
        )

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _cb_play(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        return [
            AnswerCallback(callback_id),
            *self._begin_match(chat_id, state),
        ]

    def _cb_roster(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        return [AnswerCallback(callback_id), *self._show_roster(chat_id, state)]

    def _cb_pick(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        roster = state.match_context.get("roster") or []
        try:
            index = int(argument)
        except (TypeError, ValueError):
            return [AnswerCallback(callback_id, "That choice is no longer available.")]
        if not 1 <= index <= len(roster):
            return [AnswerCallback(callback_id, "That choice is no longer available.")]

        mint, name = roster[index - 1]
        if state.session_token is None:
            return [AnswerCallback(callback_id, "Connect a wallet first.", alert=True)]
        try:
            fighter = self._app.wallets.fighter_for(state.session_token, mint, name=name)
        except OwnershipRequired as exc:
            return [AnswerCallback(callback_id, str(exc), alert=True)]
        except AuthError:
            state.session_token = None
            return [AnswerCallback(callback_id, "Your session expired.", alert=True)]
        except Exception:
            logger.exception("could not confirm ownership for a pick")
            return [AnswerCallback(callback_id, "I could not check that just now.", alert=True)]

        state.chosen_mint = mint
        state.chosen_name = name
        return [
            AnswerCallback(callback_id, "Fighter chosen."),
            SendMessage(
                chat_id,
                render.code_block(f"Your fighter:\n\n  {render.fighter_line(fighter)}"),
                render.menu_keyboard(self._signer.sign, state.user_id, has_wallet=True),
            ),
        ]

    def _cb_soul(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        if state.match is None or state.match.is_over:
            return [AnswerCallback(callback_id, "That match is over.")]
        view = state.match.view(Side.A)
        if not view.can_spend_soul:
            return [AnswerCallback(callback_id, "Not enough soul yet.")]
        state.soul_armed = not state.soul_armed
        note = f"{view.arena.soul_name} armed." if state.soul_armed else "Soul held."
        return [
            AnswerCallback(callback_id, note),
            EditMessage(
                chat_id,
                message_id,
                render.code_block(
                    render.board_text(view, header=note)
                ),
                self._match_keyboard(state),
            ),
        ]

    def _cb_quit(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        if state.match is None:
            return [AnswerCallback(callback_id, "No match running.")]
        state.end_match()
        return [
            AnswerCallback(callback_id, "Forfeited."),
            EditMessage(
                chat_id,
                message_id,
                render.code_block("You forfeited. /play for another."),
                render.menu_keyboard(
                    self._signer.sign, state.user_id, has_wallet=state.session_token is not None
                ),
            ),
        ]

    def _cb_stance(self, callback_id, chat_id, message_id, state, argument) -> list[Action]:
        """Resolve one round.

        Both sides decide simultaneously, exactly as in the CLI: the agent is
        handed the same `MatchView` a player gets, so it cannot see the stance
        it is being asked to answer.
        """
        match = state.match
        if match is None or match.is_over:
            return [AnswerCallback(callback_id, "That match is over. Send /play.")]

        try:
            stance = Stance(argument)
        except ValueError:
            return [AnswerCallback(callback_id, "Unknown move.")]

        context = state.match_context
        agent = context["agent"]
        names = context["names"]
        narrator = context["narrator"]

        decisions = {
            Side.A: Decision(stance=stance, spend_soul=state.soul_armed),
            Side.B: agent.decide(match.view(Side.B)),
        }
        state.soul_armed = False
        events = match.submit(decisions)

        body_parts = [render.round_text(events, names, self._app.content, narrator)]
        if match.is_over:
            outcome = match.outcome
            body_parts.append(
                render.outcome_text(outcome, names, self._app.content, narrator, Side.A)
            )
            state.end_match()
            keyboard = render.menu_keyboard(
                self._signer.sign, state.user_id, has_wallet=state.session_token is not None
            )
        else:
            body_parts.append("")
            body_parts.append(render.board_text(match.view(Side.A)))
            keyboard = self._match_keyboard(state)

        return [
            AnswerCallback(callback_id),
            EditMessage(
                chat_id,
                message_id,
                render.code_block("\n".join(p for p in body_parts if p is not None)),
                keyboard,
            ),
        ]


def _synthetic_mint(rng: RNG) -> str:
    """A valid, decodable address for a computer-controlled rival.

    Derived from the match seed rather than the clock, so a replayed match
    faces the same rival. It is a real base58 address in shape and nothing
    else -- no NFT is claimed to exist at it.
    """
    from ..security.validation import b58encode  # noqa: PLC0415

    material = b"".join(rng.below(256).to_bytes(1, "big") for _ in range(32))
    return b58encode(material)


#: Command name to handler. A table rather than a chain of `if`s, so the set of
#: things the bot responds to is one readable list.
_COMMANDS: Final[Mapping[str, Any]] = {
    "/start": BotHandlers._cmd_start,
    "/help": BotHandlers._cmd_help,
    "/play": BotHandlers._cmd_play,
    "/connect": BotHandlers._cmd_connect,
    "/signed": BotHandlers._cmd_signed,
    "/roster": BotHandlers._cmd_roster,
    "/whoami": BotHandlers._cmd_whoami,
    "/disconnect": BotHandlers._cmd_disconnect,
}

_CALLBACKS: Final[Mapping[str, Any]] = {
    render.ACTION_STANCE: BotHandlers._cb_stance,
    render.ACTION_SOUL: BotHandlers._cb_soul,
    render.ACTION_PLAY: BotHandlers._cb_play,
    render.ACTION_PICK: BotHandlers._cb_pick,
    render.ACTION_ROSTER: BotHandlers._cb_roster,
    render.ACTION_QUIT: BotHandlers._cb_quit,
}
