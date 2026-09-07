"""A full-cycle simulation: many players, many fights, every way it can break.

The unit tests answer "does this function do what it says". This answers a
different question: **what happens when a few hundred people use the thing at
once, and a quarter of them are hostile, and the chain goes down in the middle
of it.**

Run it:

    python tools/simulate.py                      # the default profile
    python tools/simulate.py --players 500 --json out.json --html out.html
    python tools/simulate.py --phase abuse        # one phase only

Nothing here touches a network, a database or a real wallet. The sandbox in
`tools/sandbox.py` provides real ed25519 keypairs, a dictionary for a chain and
a queue for Telegram, so a signature is a real signature and an outage is a
real outage, but there is nothing to break outside this process.

## The phases

| Phase | What it proves |
|---|---|
| `lifecycle` | the happy path, end to end, for every player |
| `interrupted` | every way a fight can be cut in half |
| `abuse` | forged, stolen, replayed and malformed input |
| `outage` | the chain going down mid-session, and coming back |
| `simultaneous` | every player fighting at once, advanced round by round |
| `concurrency` | many players in flight at once, on real threads |
| `soak` | a long weighted random walk over every command |

## The invariants

Checked continuously, not at the end, because a violation's *cause* is the
action right before it. Every one of these is a real bug class:

* no message exceeds Telegram's limit -- an over-long message is silently
  rejected by the API;
* no full wallet address, and no session token, ever reaches a message;
* every fenced block is balanced, and no attacker-written text escapes it;
* every callback payload fits in 64 bytes and verifies for its owner;
* the conversation store and the rate limiter stay bounded;
* `handle()` never raises -- a bot that dies on one update is a bot anyone
  can stop.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox import (  # noqa: E402
    HOSTILE_NAMES,
    Sandbox,
    SandboxWallet,
    build_sandbox,
    button_update,
    make_wallets,
    stock_wallet,
    text_update,
)

from rivalforge.content.loader import load_content  # noqa: E402
from rivalforge.engine import balance  # noqa: E402
from rivalforge.engine.match import Side  # noqa: E402
from rivalforge.engine.rng import RNG  # noqa: E402
from rivalforge.telegram import render  # noqa: E402
from rivalforge.telegram.api import MAX_MESSAGE_CHARS  # noqa: E402
from rivalforge.telegram.security import MAX_CALLBACK_BYTES, CallbackError  # noqa: E402

STANCES = ("strike", "guard", "focus")

#: Solana-shaped. Used to find candidate addresses in a message cheaply.
_BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")


# ==========================================================================
# Invariants
# ==========================================================================


@dataclass
class Violation:
    """One broken invariant, with enough context to reproduce it."""

    invariant: str
    phase: str
    action: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "invariant": self.invariant,
            "phase": self.phase,
            "action": self.action,
            "detail": self.detail,
        }


class Guard:
    """Checks every message and every button the bot produces.

    Runs after each action rather than at the end: a violation's cause is the
    action immediately before it, and a report that says "somewhere in 40,000
    messages" is a report nobody can act on.

    Sends and edits are tracked as two separate cursors. An earlier version
    concatenated the two lists and kept one index into the result -- which
    shifted every time a send landed, so already-checked edits were re-checked
    against the wrong player and reported as forged buttons. The harness has
    to be trustworthy before its findings are.
    """

    def __init__(self, sandbox: Sandbox) -> None:
        self._sandbox = sandbox
        self._seen_sent = 0
        self._seen_edited = 0
        self.violations: list[Violation] = []
        self.messages_checked = 0
        self.buttons_checked = 0
        self.secrets: set[str] = set()
        self.wallet_owner: dict[str, int] = {}
        self._lock = threading.Lock()

    def watch_secret(self, value: str) -> None:
        """Register a bearer credential. These may never appear anywhere."""
        if value:
            with self._lock:
                self.secrets.add(value)

    def watch_wallet(self, address: str, chat_id: int) -> None:
        """Register a wallet and the one chat it is allowed to appear in.

        A wallet address is *not* a secret -- it is public on-chain, and the
        challenge a player signs has to contain it, because a wallet must show
        the owner which address they are authenticating. What would be a real
        leak is that address turning up in somebody else's chat, so that is
        what this checks.
        """
        if address:
            with self._lock:
                self.wallet_owner[address] = chat_id

    def _fail(self, invariant: str, phase: str, action: str, detail: str) -> None:
        with self._lock:
            self.violations.append(Violation(invariant, phase, action, detail[:300]))

    def check(self, phase: str, action: str) -> None:
        """Inspect everything produced since the last call.

        The expected owner of a button is taken from the chat it was sent to,
        not from whoever happened to act last -- in a private chat the chat id
        *is* the user id, so a button signed for anyone else is a real finding.
        """
        api = self._sandbox.api
        with api._lock:  # noqa: SLF001 -- the harness owns this object
            sent = api.sent[self._seen_sent:]
            edited = api.edited[self._seen_edited:]
            self._seen_sent = len(api.sent)
            self._seen_edited = len(api.edited)

        for chat_id, text, keyboard in sent:
            self._check_message(text, phase, action, chat_id)
            self._check_keyboard(keyboard, phase, action, chat_id)
        for chat_id, _message_id, text, keyboard in edited:
            self._check_message(text, phase, action, chat_id)
            self._check_keyboard(keyboard, phase, action, chat_id)

        self._check_bounds(phase, action)

    def _check_message(self, text: str, phase: str, action: str, chat_id: int) -> None:
        self.messages_checked += 1

        if len(text) > MAX_MESSAGE_CHARS:
            self._fail(
                "message fits Telegram's limit", phase, action,
                f"{len(text)} characters, over {MAX_MESSAGE_CHARS}",
            )

        with self._lock:
            secrets = tuple(self.secrets)
            owners = dict(self.wallet_owner)

        for secret in secrets:
            if secret in text:
                self._fail(
                    "a session token never reaches a message", phase, action,
                    f"a bearer token appeared in a message of {len(text)} chars",
                )

        # Pull the address-shaped substrings out once and intersect, rather
        # than searching the message once per known wallet. With a thousand
        # players the second form is the difference between a campaign that
        # finishes and one that does not.
        if owners:
            for candidate in _BASE58.findall(text):
                owner_chat = owners.get(candidate)
                if owner_chat is not None and owner_chat != chat_id:
                    self._fail(
                        "a wallet appears only in its owner's chat", phase, action,
                        f"a wallet belonging to chat {owner_chat} appeared in chat {chat_id}",
                    )

        # A fenced block must be balanced, or everything after it is parsed as
        # markup -- which is the whole formatting-injection threat.
        if text.count("```") % 2 != 0:
            self._fail("fenced blocks are balanced", phase, action, text[:120])

        if text.startswith("```"):
            body = text[3:-3] if text.endswith("```") else text[3:]
            # Inside a block, an unescaped backtick closes it early.
            for match in re.finditer(r"`", body):
                start = match.start()
                if start == 0 or body[start - 1] != "\\":
                    self._fail(
                        "no unescaped backtick inside a block", phase, action, body[:160]
                    )
                    break

        # Attacker-written link syntax must never survive to a rendered link.
        if "](http" in text and "\\]" not in text:
            self._fail("no clickable link from foreign text", phase, action, text[:160])

    def _check_keyboard(
        self, keyboard: Any, phase: str, action: str, chat_id: int
    ) -> None:
        if not keyboard:
            return
        # A group chat id is negative and is not a user id, so ownership is
        # not checkable there -- and no button is ever offered in one.
        owner = chat_id if chat_id > 0 else None
        for row in keyboard:
            for button in row:
                self.buttons_checked += 1
                data = button.get("callback_data", "")
                size = len(data.encode("utf-8"))
                if size > MAX_CALLBACK_BYTES:
                    self._fail(
                        "callback_data fits Telegram's limit", phase, action,
                        f"{size} bytes for {data!r}",
                    )
                if owner is not None:
                    try:
                        self._sandbox.signer.verify(data, owner)
                    except CallbackError:
                        self._fail(
                            "every button verifies for the chat it was sent to",
                            phase, action,
                            f"{data!r} did not verify for user {owner}",
                        )

    def _check_bounds(self, phase: str, action: str) -> None:
        states = self._sandbox.states
        limit = states._max_users  # noqa: SLF001 -- the harness owns this object
        if len(states) > limit:
            self._fail(
                "the conversation store stays bounded", phase, action,
                f"{len(states)} conversations, limit {limit}",
            )


# ==========================================================================
# Metrics
# ==========================================================================


class Metrics:
    """Everything counted, with a lock because the concurrency phase is real."""

    def __init__(self) -> None:
        self.actions: Counter[str] = Counter()
        self.outcomes: Counter[str] = Counter()
        self.errors: Counter[str] = Counter()
        self.rounds: Counter[int] = Counter()
        self.arenas: Counter[str] = Counter()
        self.final_bp: list[int] = []
        self.notes: list[str] = []
        self.examples: dict[str, list[str]] = defaultdict(list)
        self.phase_timing: dict[str, float] = {}
        self._lock = threading.Lock()

    def act(self, name: str, count: int = 1) -> None:
        with self._lock:
            self.actions[name] += count

    def outcome(self, name: str, count: int = 1) -> None:
        with self._lock:
            self.outcomes[name] += count

    def error(self, name: str) -> None:
        with self._lock:
            self.errors[name] += 1

    def match_finished(self, outcome, arena_name: str) -> None:
        with self._lock:
            self.rounds[outcome.rounds] += 1
            self.arenas[arena_name] += 1
            self.final_bp.append(max(outcome.final_bp.values()))

    def example(self, key: str, text: str, limit: int = 4) -> None:
        with self._lock:
            if len(self.examples[key]) < limit:
                self.examples[key].append(text[:400])

    def note(self, text: str) -> None:
        with self._lock:
            self.notes.append(text)


# ==========================================================================
# A player
# ==========================================================================


@dataclass
class Player:
    """One virtual person: a Telegram id, a wallet, and whatever they are doing."""

    user_id: int
    wallet: SandboxWallet
    chat_id: int
    rng: random.Random
    connected: bool = False
    roster_size: int = 0
    fights_started: int = 0
    fights_finished: int = 0
    fights_abandoned: int = 0
    wins: int = 0
    losses: int = 0
    draws: int = 0
    match_ref: Any = None
    board_message_id: int = 1
    label: str = "honest"


# ==========================================================================
# The driver
# ==========================================================================


class Simulation:
    """Drives a sandbox through every phase and records what happened."""

    def __init__(self, sandbox: Sandbox, *, seed: int = 20260907, verbose: bool = False) -> None:
        self.sandbox = sandbox
        self.guard = Guard(sandbox)
        self.metrics = Metrics()
        self.rng = random.Random(seed)
        self.verbose = verbose
        self.phase = "setup"
        # Thread-local. The concurrency phase runs real threads, and a shared
        # "the last reply" is wrong the moment two players act at once -- it
        # reported one player's board as another's outcome and looked exactly
        # like a rendering bug in the product. Three harness bugs in this file
        # have now had the same shape: state that is fine for one actor and
        # wrong for two.
        self._local = threading.local()
        self._sample_every = 25
        self._since_sample = 0
        self.peak_live_matches = 0
        self.live_samples: list[int] = []

    # -- plumbing ---------------------------------------------------------

    def send(self, player: Player, update: dict[str, Any], *, action: str) -> list[Any]:
        """Deliver one update and check every invariant it touched.

        `handle()` is called directly rather than through the poll loop: the
        loop is covered by its own tests, and calling it here would hide which
        update produced which message.
        """
        self.metrics.act(action)
        try:
            actions = self.sandbox.handlers.handle(update)
        except BaseException as exc:  # noqa: BLE001 -- that is the invariant
            self.guard._fail(  # noqa: SLF001
                "handle() never raises", self.phase, action,
                f"{type(exc).__name__}: {exc}",
            )
            self.metrics.error(f"handle raised {type(exc).__name__}")
            return []

        self._local.texts = self._perform(actions, player)
        self.guard.check(self.phase, action)
        self._sample_live_matches()
        return actions

    def _perform(self, actions: Iterable[Any], player: Player) -> list[str]:
        """Apply the actions the way `bot.py` does, and track the board message.

        Returns the text each action produced, in order. The caller needs
        *this* update's replies, not the newest entry in a shared log -- an
        earlier version read the latter and silently compared one player's
        reply against another's.
        """
        api = self.sandbox.api
        produced: list[str] = []
        for action in actions:
            name = type(action).__name__
            try:
                if name == "SendMessage":
                    result = api.send_message(
                        action.chat_id, action.text, keyboard=action.keyboard
                    )
                    produced.append(action.text)
                    if action.keyboard:
                        player.board_message_id = result["message_id"]
                elif name == "EditMessage":
                    api.edit_message_text(
                        action.chat_id, action.message_id, action.text,
                        keyboard=action.keyboard,
                    )
                    produced.append(action.text)
                elif name == "AnswerCallback":
                    api.answer_callback_query(
                        action.callback_id, text=action.text, alert=action.alert
                    )
                    produced.append(action.text)
            except RuntimeError:
                # An injected transport failure. The loop logs and moves on;
                # so does this.
                self.metrics.outcome("transport failure absorbed")
        return produced

    def _sample_live_matches(self) -> None:
        """How many fights are in progress at once, sampled rather than counted.

        Counting on every action would be O(conversations) per update, which at
        campaign scale costs more than the thing being measured. Sampling gives
        the shape of the answer for a fraction of the price, and the report says
        it is sampled.
        """
        self._since_sample += 1
        if self._since_sample < self._sample_every:
            return
        self._since_sample = 0
        states = self.sandbox.states
        with states._lock:  # noqa: SLF001 -- the harness owns this object
            live = sum(1 for s in states._states.values() if s.match is not None)  # noqa: SLF001
        self.live_samples.append(live)
        if live > self.peak_live_matches:
            self.peak_live_matches = live

    def state_of(self, player: Player):
        return self.sandbox.states.get(player.user_id)

    def last_text(self) -> str:
        """The text the most recent update produced -- not the newest in the log.

        With many players interleaved, "the newest message anywhere" belongs to
        whoever acted last, which is rarely the player being asked about.
        """
        texts = getattr(self._local, "texts", None)
        return texts[-1] if texts else ""

    # -- the pieces of a session -----------------------------------------

    def start(self, player: Player) -> None:
        self.send(player, text_update(player.user_id, "/start", chat_id=player.chat_id),
                  action="/start")

    def connect(self, player: Player, *, correct: bool = True) -> bool:
        """Full connect flow: challenge, sign, verify.

        The message to sign is read out of the bot's own reply -- the string a
        player would actually copy into their wallet -- rather than out of the
        challenge store.
        """
        self.send(
            player,
            text_update(player.user_id, f"/connect {player.wallet.address}",
                        chat_id=player.chat_id),
            action="/connect",
        )
        body = self.last_text()
        _, _, rest = body.partition("----- message to sign -----\n")
        signable, _, _ = rest.partition("\n---------------------------")
        if not signable:
            self.metrics.outcome("challenge not issued")
            return False

        signature = (
            player.wallet.sign(signable) if correct else player.wallet.garbage_signature()
        )
        self.send(
            player,
            text_update(player.user_id, f"/signed {signature}", chat_id=player.chat_id),
            action="/signed",
        )
        ok = "Connected" in self.last_text()
        player.connected = ok
        self.metrics.outcome("login succeeded" if ok else "login rejected")
        if ok:
            token = self.state_of(player).session_token
            self.guard.watch_secret(token)
            self.guard.watch_wallet(player.wallet.address, player.chat_id)
            self.metrics.example("connected", self.last_text())
        else:
            self.metrics.example("login rejected", self.last_text())
        return ok

    def roster(self, player: Player) -> int:
        self.send(player, text_update(player.user_id, "/roster", chat_id=player.chat_id),
                  action="/roster")
        text = self.last_text()
        if "could not read" in text:
            self.metrics.outcome("roster unavailable (outage, not a denial)")
            return 0
        if "Connect a wallet first" in text or "expired" in text:
            self.metrics.outcome("roster refused without a session")
            return 0
        entries = len(re.findall(r"^\s*\d+\. ", text, flags=re.MULTILINE))
        player.roster_size = entries
        # An empty wallet is a legitimate answer and a different one from an
        # outage. Conflating them is the mistake this whole design avoids.
        self.metrics.outcome("roster shown" if entries else "roster shown (wallet is empty)")
        self.metrics.example("roster", text)
        return entries

    def pick(self, player: Player, index: int) -> bool:
        self.send(
            player,
            button_update(player.user_id, self.sandbox.sign(render.ACTION_PICK, str(index),
                                                            player.user_id),
                          chat_id=player.chat_id, message_id=player.board_message_id),
            action="pick fighter",
        )
        chosen = self.state_of(player).chosen_mint is not None
        self.metrics.outcome("fighter chosen" if chosen else "fighter pick refused")
        return chosen

    def play(self, player: Player) -> bool:
        self.send(player, text_update(player.user_id, "/play", chat_id=player.chat_id),
                  action="/play")
        state = self.state_of(player)
        player.match_ref = state.match
        if player.match_ref is None:
            self.metrics.outcome("match failed to start")
            return False
        player.fights_started += 1
        self.metrics.outcome("fight started")
        return True

    def stance(self, player: Player, stance: str | None = None) -> None:
        stance = stance or player.rng.choice(STANCES)
        self.send(
            player,
            button_update(
                player.user_id,
                self.sandbox.sign(render.ACTION_STANCE, stance, player.user_id),
                chat_id=player.chat_id, message_id=player.board_message_id,
            ),
            action=f"stance:{stance}",
        )

    def arm_soul(self, player: Player) -> None:
        self.send(
            player,
            button_update(
                player.user_id,
                self.sandbox.sign(render.ACTION_SOUL, "toggle", player.user_id),
                chat_id=player.chat_id, message_id=player.board_message_id,
            ),
            action="arm soul",
        )

    def fight_to_the_end(self, player: Player, *, max_rounds: int = 40) -> None:
        """Play a match out, spending soul whenever there is any."""
        match = player.match_ref
        for _ in range(max_rounds):
            if match is None or match.is_over:
                break
            if match.view(Side.A).can_spend_soul and player.rng.random() < 0.6:
                self.arm_soul(player)
            self.stance(player)
        self._record_finish(player)

    def _record_finish(self, player: Player) -> None:
        match = player.match_ref
        if match is None or not match.is_over:
            return
        outcome = match.outcome
        player.fights_finished += 1
        self.metrics.match_finished(outcome, match.view(Side.A).arena.name)
        if outcome.winner is Side.A:
            player.wins += 1
            self.metrics.outcome("player won")
        elif outcome.winner is Side.B:
            player.losses += 1
            self.metrics.outcome("player lost")
        else:
            player.draws += 1
            self.metrics.outcome("draw")
        self.metrics.example("finished fight", self.last_text())

        # Cross-check: the engine's verdict and the rendered text must agree.
        text = self.last_text()
        if outcome.winner is None and "DRAW" not in text:
            self.guard._fail(  # noqa: SLF001
                "the rendered outcome matches the engine's", self.phase,
                "finish", "engine says draw, message does not",
            )
        if outcome.winner is not None and "wins in" not in text:
            self.guard._fail(  # noqa: SLF001
                "the rendered outcome matches the engine's", self.phase,
                "finish", "engine says a winner, message does not",
            )
        player.match_ref = None

    def disconnect(self, player: Player) -> None:
        self.send(player, text_update(player.user_id, "/disconnect", chat_id=player.chat_id),
                  action="/disconnect")
        player.connected = False
        self.metrics.outcome("logged out")

    # ======================================================================
    # Phases
    # ======================================================================

    def phase_lifecycle(self, players: list[Player]) -> None:
        """The happy path, end to end, for everybody."""
        self.phase = "lifecycle"
        for player in players:
            self.start(player)
            if self.connect(player):
                count = self.roster(player)
                if count:
                    self.pick(player, player.rng.randint(1, count))
                self.send(player, text_update(player.user_id, "/whoami",
                                              chat_id=player.chat_id), action="/whoami")
            for _ in range(player.rng.randint(1, 3)):
                if self.play(player):
                    self.fight_to_the_end(player)
            self.send(player, text_update(player.user_id, "/help", chat_id=player.chat_id),
                      action="/help")
            self.disconnect(player)

    def phase_interrupted(self, players: list[Player]) -> None:
        """Every way a fight can be cut in half.

        Each of these leaves state somewhere the happy path never does, which
        is exactly where a chat bot rots.
        """
        self.phase = "interrupted"
        cases: list[tuple[str, Callable[[Player], None]]] = [
            ("forfeit mid-fight", self._cut_forfeit),
            ("disconnect mid-fight", self._cut_disconnect),
            ("session expires mid-fight", self._cut_expiry),
            ("conversation evicted mid-fight", self._cut_eviction),
            ("NFT sold mid-fight", self._cut_sold),
            ("second /play mid-fight", self._cut_replay),
            ("stance after the match ended", self._cut_late_stance),
            ("bot restarted mid-fight", self._cut_restart),
            ("wandered off mid-fight", self._cut_abandon),
        ]
        for index, (label, case) in enumerate(cases):
            for player in players[: max(1, len(players) // len(cases))]:
                player.label = label
                self.connect(player)
                if not self.play(player):
                    continue
                for _ in range(player.rng.randint(1, 4)):
                    self.stance(player)
                try:
                    case(player)
                    self.metrics.outcome(f"survived: {label}")
                except Exception as exc:  # noqa: BLE001
                    self.metrics.error(f"{label}: {type(exc).__name__}")
                    self.guard._fail(  # noqa: SLF001
                        "an interrupted fight never breaks the bot",
                        self.phase, label, f"{type(exc).__name__}: {exc}",
                    )
                player.fights_abandoned += 1
                # Whatever happened, the player must be able to start again.
                self.send(player, text_update(player.user_id, "/play",
                                              chat_id=player.chat_id), action="/play (recover)")
                if self.state_of(player).match is None:
                    self.guard._fail(  # noqa: SLF001
                        "a player can always start again", self.phase, label,
                        "the next /play did not start a match",
                    )
                self.state_of(player).end_match()

    def _cut_forfeit(self, player: Player) -> None:
        self.send(
            player,
            button_update(player.user_id,
                          self.sandbox.sign(render.ACTION_QUIT, "match", player.user_id),
                          chat_id=player.chat_id, message_id=player.board_message_id),
            action="forfeit",
        )

    def _cut_disconnect(self, player: Player) -> None:
        self.disconnect(player)
        self.stance(player)  # a button from a conversation that no longer exists

    def _cut_expiry(self, player: Player) -> None:
        self.sandbox.clock.advance(hours=3)
        self.stance(player)
        self.roster(player)

    def _cut_eviction(self, player: Player) -> None:
        self.sandbox.states.forget(player.user_id)
        self.stance(player)

    def _cut_sold(self, player: Player) -> None:
        self.sandbox.chain.sell_everything(player.wallet.address)
        self.stance(player)
        self.send(player, text_update(player.user_id, "/play", chat_id=player.chat_id),
                  action="/play after selling")

    def _cut_replay(self, player: Player) -> None:
        first = self.state_of(player).match
        self.send(player, text_update(player.user_id, "/play", chat_id=player.chat_id),
                  action="/play mid-fight")
        if self.state_of(player).match is first:
            self.guard._fail(  # noqa: SLF001
                "a second /play starts a new match", self.phase, "second /play",
                "the old match was still in place",
            )

    def _cut_late_stance(self, player: Player) -> None:
        self.state_of(player).end_match()
        self.stance(player)
        if "over" not in " ".join(t for _, t in self.sandbox.api.answered[-2:]):
            self.metrics.note("a stance after the end was not explained")

    def _cut_restart(self, player: Player) -> None:
        """What a container restart looks like from a player's seat."""
        self.sandbox.states.forget(player.user_id)
        self.stance(player)
        self.start(player)

    def _cut_abandon(self, player: Player) -> None:
        """They simply stop replying. The state has to age out on its own."""
        self.sandbox.states.forget(player.user_id)

    def phase_abuse(self, players: list[Player]) -> None:
        """Forged, stolen, replayed and malformed input."""
        self.phase = "abuse"
        victim, attacker = players[0], players[1 % len(players)]
        self.connect(victim)
        self.connect(attacker)
        self.play(victim)

        # A button signed for someone else.
        stolen = self.sandbox.sign(render.ACTION_STANCE, "strike", victim.user_id)
        before = victim.match_ref.round_number if victim.match_ref else 0
        self.send(attacker, button_update(attacker.user_id, stolen, chat_id=attacker.chat_id),
                  action="stolen button")
        after = victim.match_ref.round_number if victim.match_ref else 0
        if after != before:
            self.guard._fail(  # noqa: SLF001
                "a stolen button never moves another player's match",
                self.phase, "stolen button", f"round went {before} -> {after}",
            )
        self.metrics.outcome("stolen button rejected")

        # Forged, truncated, oversized and nonsense payloads.
        for label, payload in (
            ("forged signature", "st|strike|AAAAAAAAAAAAAAAA"),
            ("missing signature", "st|strike"),
            ("empty", ""),
            ("oversized", "x" * 200),
            ("wrong separator count", "a|b|c|d"),
            ("unknown action", self.sandbox.sign("zz", "x", attacker.user_id)),
            ("nonsense", "🙂" * 10),
        ):
            self.send(attacker, button_update(attacker.user_id, payload,
                                              chat_id=attacker.chat_id),
                      action=f"bad callback: {label}")
            self.metrics.outcome("bad callback rejected")

        # Wallet flows in a group.
        for command in (f"/connect {attacker.wallet.address}", "/signed abc", "/roster"):
            self.send(
                attacker,
                text_update(attacker.user_id, command, chat_id=-1001234567890,
                            chat_type="supergroup"),
                action="group chat wallet flow",
            )
            if "direct message" not in self.last_text():
                self.guard._fail(  # noqa: SLF001
                    "wallet flows are private-chat only", self.phase, command,
                    self.last_text()[:120],
                )
            self.metrics.outcome("group wallet flow refused")

        # A wrong signature, then the correct one for a burnt challenge.
        self.connect(attacker, correct=False)
        self.metrics.outcome("wrong signature rejected")

        # Replaying a consumed nonce.
        self.send(attacker, text_update(attacker.user_id, f"/connect {attacker.wallet.address}",
                                        chat_id=attacker.chat_id), action="/connect")
        body = self.last_text()
        _, _, rest = body.partition("----- message to sign -----\n")
        signable, _, _ = rest.partition("\n---------------------------")
        signature = attacker.wallet.sign(signable)
        self.send(attacker, text_update(attacker.user_id, f"/signed {signature}",
                                        chat_id=attacker.chat_id), action="/signed")
        self.send(attacker, text_update(attacker.user_id, f"/signed {signature}",
                                        chat_id=attacker.chat_id), action="/signed (replay)")
        if "Connected" in self.last_text():
            self.guard._fail(  # noqa: SLF001
                "a challenge is single use", self.phase, "replayed signature",
                "the second /signed succeeded",
            )
        self.metrics.outcome("replayed signature rejected")

        # Someone else's signature over our challenge.
        self.send(victim, text_update(victim.user_id, f"/connect {victim.wallet.address}",
                                      chat_id=victim.chat_id), action="/connect")
        body = self.last_text()
        _, _, rest = body.partition("----- message to sign -----\n")
        signable, _, _ = rest.partition("\n---------------------------")
        self.send(victim, text_update(victim.user_id, f"/signed {attacker.wallet.sign(signable)}",
                                      chat_id=victim.chat_id), action="/signed (wrong key)")
        if "Connected" in self.last_text():
            self.guard._fail(  # noqa: SLF001
                "only the wallet's own key authenticates", self.phase, "wrong key",
                "another wallet's signature was accepted",
            )
        self.metrics.outcome("wrong-key signature rejected")

        # Malformed updates: shapes Telegram would never send, and one it might.
        for label, update in (
            ("not a mapping", None),
            ("empty", {}),
            ("no sender", {"message": {"chat": {"id": 1, "type": "private"}, "text": "/play"}}),
            ("from another bot", text_update(attacker.user_id, "/play", is_bot=True)),
            ("no text", {"update_id": 1, "message": {
                "message_id": 1, "from": {"id": attacker.user_id, "is_bot": False},
                "chat": {"id": attacker.chat_id, "type": "private"}}}),
            ("absurd text", text_update(attacker.user_id, "/play " + "x" * 200_000)),
            ("negative user id", text_update(-5, "/play")),
            ("float user id", {"update_id": 1, "message": {
                "message_id": 1, "from": {"id": 1.5, "is_bot": False},
                "chat": {"id": 1, "type": "private"}, "text": "/play"}}),
            ("unknown command", text_update(attacker.user_id, "/definitely-not-a-command")),
            ("command with bot name", text_update(attacker.user_id, "/help@SandboxBot")),
        ):
            self.metrics.act(f"malformed: {label}")
            try:
                self.sandbox.handlers.handle(update)
            except BaseException as exc:  # noqa: BLE001
                self.guard._fail(  # noqa: SLF001
                    "handle() never raises", self.phase, f"malformed: {label}",
                    f"{type(exc).__name__}: {exc}",
                )
            self.guard.check(self.phase, f"malformed: {label}")
            self.metrics.outcome("malformed update absorbed")

        # A flood, from a limiter tightened for the occasion.
        tight = build_sandbox(rate_capacity=5, rate_refill=0.001, content=self.sandbox.content)
        flooder = Player(user_id=99_001, wallet=players[0].wallet, chat_id=99_001,
                         rng=random.Random(1))
        allowed = 0
        for _ in range(200):
            if tight.handlers.handle(text_update(flooder.user_id, "/help")):
                allowed += 1
        self.metrics.outcome("flood dropped", 200 - allowed)
        if allowed > 5:
            self.guard._fail(  # noqa: SLF001
                "a flood is capped", self.phase, "flood",
                f"{allowed} of 200 got through a capacity-5 bucket",
            )
        self.metrics.note(f"flood: {allowed} of 200 served, {200 - allowed} dropped in silence")

    def phase_outage(self, players: list[Player]) -> None:
        """The chain goes down mid-session, and comes back."""
        self.phase = "outage"
        chain = self.sandbox.chain
        for player in players[:20]:
            self.connect(player)

        chain.hard_down = True
        for player in players[:20]:
            self.roster(player)
            text = self.last_text()
            if "no NFTs" in text.lower():
                self.guard._fail(  # noqa: SLF001
                    "an outage is not an empty wallet", self.phase, "roster during outage",
                    text[:120],
                )
            # Ownership must fail *closed*: no fighter is granted while we
            # cannot confirm it, which is the opposite of the roster rule.
            if self.play(player):
                state = self.state_of(player)
                if state.chosen_mint is not None:
                    self.guard._fail(  # noqa: SLF001
                        "ownership fails closed during an outage", self.phase, "/play",
                        "a mint stayed selected while the chain was down",
                    )
                state.end_match()
            self.metrics.outcome("degraded gracefully during outage")

        chain.hard_down = False
        recovered = 0
        eligible = 0
        for player in players[:20]:
            if not player.connected:
                continue
            eligible += 1
            self.roster(player)
            if "could not read" not in self.last_text():
                recovered += 1
        self.metrics.note(
            f"after recovery, {recovered}/{eligible} rosters answered again "
            "(an empty wallet counts: it is an answer, not an outage)"
        )
        if eligible and recovered == 0:
            self.guard._fail(  # noqa: SLF001
                "the bot recovers when the chain does", self.phase, "recovery",
                "no roster loaded after the outage ended",
            )

    def phase_concurrency(self, players: list[Player], *, threads: int) -> None:
        """Many players in flight at once, on real threads.

        `Bot` polls on one thread by design, so this drives `handle()` directly
        -- which is where the shared state actually is: the conversation store,
        the rate limiter, the challenge store and the session store.
        """
        self.phase = "concurrency"
        errors: list[str] = []
        barrier = threading.Barrier(threads)

        def run(subset: list[Player]) -> None:
            barrier.wait()
            for player in subset:
                try:
                    self.connect(player)
                    self.roster(player)
                    if self.play(player):
                        for _ in range(6):
                            if player.match_ref is None or player.match_ref.is_over:
                                break
                            self.stance(player)
                        self._record_finish(player)
                    self.disconnect(player)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(f"{type(exc).__name__}: {exc}")

        chunk = max(1, len(players) // threads)
        workers = [
            threading.Thread(target=run, args=(players[i:i + chunk],))
            for i in range(0, chunk * threads, chunk)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=180)

        for error in errors:
            self.metrics.error(f"concurrent: {error}")
            self.guard._fail(  # noqa: SLF001
                "concurrent players do not collide", self.phase, "parallel session", error
            )
        self.metrics.note(
            f"{threads} threads x ~{chunk} players concurrently; {len(errors)} errors"
        )

    def phase_simultaneous(self, players: list[Player]) -> None:
        """Every player fighting at once, advanced round by round.

        This is the interleaving case: not "many fights" but "many fights
        *in flight together*", each holding its own RNG stream, arena, soul
        state and round history. If any of that were shared -- a module-level
        RNG, a global "current match", a cached fighter -- this is where it
        would show, because a leak between two matches changes an outcome and
        nothing else would notice.
        """
        self.phase = "simultaneous"
        opened = []
        for player in players:
            if self.play(player):
                opened.append(player)
        self.metrics.note(f"{len(opened)} fights opened before any of them advanced")

        # A fingerprint of each match, to prove none of them drifted into
        # another's state.
        seeds = {p.user_id: p.match_ref.seed for p in opened}
        arenas = {p.user_id: p.match_ref.view(Side.A).arena.id for p in opened}

        for _round in range(balance.MAX_ROUNDS + 2):
            live = [p for p in opened if p.match_ref is not None and not p.match_ref.is_over]
            if not live:
                break
            for player in live:
                if player.match_ref.view(Side.A).can_spend_soul and player.rng.random() < 0.5:
                    self.arm_soul(player)
                self.stance(player)
                if player.match_ref is not None and player.match_ref.is_over:
                    self._record_finish(player)

        for player in opened:
            state = self.state_of(player)
            match = state.match
            if match is None:
                continue
            if match.seed != seeds[player.user_id]:
                self.guard._fail(  # noqa: SLF001
                    "concurrent matches never swap state", self.phase, "round robin",
                    f"user {player.user_id} ended up on a different match seed",
                )
            if match.view(Side.A).arena.id != arenas[player.user_id]:
                self.guard._fail(  # noqa: SLF001
                    "concurrent matches never swap state", self.phase, "round robin",
                    f"user {player.user_id} changed arena mid-fight",
                )
            state.end_match()

    def phase_soak(self, players: list[Player], *, steps: int) -> None:
        """A long weighted random walk over everything a player can do."""
        self.phase = "soak"
        weights = [
            ("stance", 46), ("play", 14), ("roster", 8), ("connect", 6),
            ("disconnect", 5), ("soul", 5), ("forfeit", 4), ("start", 3),
            ("whoami", 3), ("help", 2), ("pick", 2), ("garbage", 2),
        ]
        choices = [name for name, weight in weights for _ in range(weight)]

        for _ in range(steps):
            player = self.rng.choice(players)
            action = self.rng.choice(choices)
            if action == "stance":
                if player.match_ref is not None and not player.match_ref.is_over:
                    self.stance(player)
                    if player.match_ref.is_over:
                        self._record_finish(player)
                else:
                    self.stance(player)  # a button for a match that is gone
            elif action == "play":
                self.play(player)
            elif action == "roster":
                self.roster(player)
            elif action == "connect":
                self.connect(player, correct=self.rng.random() > 0.15)
            elif action == "disconnect":
                self.disconnect(player)
            elif action == "soul":
                self.arm_soul(player)
            elif action == "forfeit":
                self._cut_forfeit(player)
            elif action == "start":
                self.start(player)
            elif action == "whoami":
                self.send(player, text_update(player.user_id, "/whoami",
                                              chat_id=player.chat_id), action="/whoami")
            elif action == "help":
                self.send(player, text_update(player.user_id, "/help",
                                              chat_id=player.chat_id), action="/help")
            elif action == "pick":
                self.pick(player, self.rng.randint(0, 30))
            else:
                self.send(player, text_update(player.user_id,
                                              self.rng.choice(list(HOSTILE_NAMES))),
                          action="garbage text")


# ==========================================================================
# Reporting
# ==========================================================================


def summarise(sim: Simulation, players: list[Player], elapsed: float) -> dict[str, Any]:
    metrics = sim.metrics
    fights_started = sum(p.fights_started for p in players)
    fights_finished = sum(p.fights_finished for p in players)
    fights_abandoned = sum(p.fights_abandoned for p in players)
    # Whatever is left was still being played when the run ended. Reporting it
    # is what makes the ledger add up, and "started" alone always overstates.
    fights_open = max(0, fights_started - fights_finished - fights_abandoned)
    rounds = metrics.rounds
    total_rounds = sum(count for _, count in rounds.items())
    mean_rounds = (
        sum(length * count for length, count in rounds.items()) / total_rounds
        if total_rounds else 0.0
    )
    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "elapsed_seconds": round(elapsed, 2),
        "players": len(players),
        "updates_handled": sum(metrics.actions.values()),
        "messages_checked": sim.guard.messages_checked,
        "buttons_checked": sim.guard.buttons_checked,
        "fights": {
            "started": fights_started,
            "finished": fights_finished,
            "abandoned": fights_abandoned,
            "unfinished when the run ended": fights_open,
            "peak simultaneous (sampled)": sim.peak_live_matches,
            "mean simultaneous (sampled)": round(
                sum(sim.live_samples) / len(sim.live_samples), 1
            ) if sim.live_samples else 0,
            "wins": sum(p.wins for p in players),
            "losses": sum(p.losses for p in players),
            "draws": sum(p.draws for p in players),
            "mean_rounds": round(mean_rounds, 2),
            "longest": max(rounds) if rounds else 0,
            "shortest": min(rounds) if rounds else 0,
            "round_histogram": dict(sorted(rounds.items())),
            "by_arena": dict(metrics.arenas.most_common()),
        },
        "actions": dict(metrics.actions.most_common()),
        "outcomes": dict(metrics.outcomes.most_common()),
        "errors": dict(metrics.errors.most_common()),
        "chain": {
            "ownership_checks": sim.sandbox.chain.calls_verify,
            "roster_reads": sim.sandbox.chain.calls_list,
            "outages_served": sim.sandbox.chain.outages_served,
        },
        "audit_events": dict(
            Counter(r.event.value for r in sim.sandbox.audit.records()).most_common()
        ),
        "state": {
            "conversations_tracked": len(sim.sandbox.states),
            "conversation_limit": sim.sandbox.states._max_users,  # noqa: SLF001
        },
        "phase_timing": dict(metrics.phase_timing),
        "notes": metrics.notes,
        "examples": {k: v for k, v in metrics.examples.items()},
        "violations": [v.as_dict() for v in sim.guard.violations],
    }


def print_report(report: dict[str, Any]) -> None:
    fights = report["fights"]
    print()
    print("=" * 74)
    print("  RivalForge simulation")
    print("=" * 74)
    if report.get("runs"):
        print(f"  simulation runs    {report['runs']:,}")
    print(f"  players            {report['players']:,}")
    print(f"  updates handled    {report['updates_handled']:,}")
    print(f"  messages checked   {report['messages_checked']:,}")
    print(f"  buttons checked    {report['buttons_checked']:,}")
    print(f"  elapsed            {report['elapsed_seconds']}s")
    print()
    print("  fights")
    print(f"    started          {fights['started']:,}")
    print(f"    finished         {fights['finished']:,}")
    print(f"    abandoned        {fights['abandoned']:,}")
    print(f"    still open       {fights['unfinished when the run ended']:,}")
    peak_key = next(
        (k for k in fights if k.startswith("peak simultaneous")), None
    )
    if peak_key:
        print(f"    peak at once     {fights[peak_key]:,}  (sampled)")
    print(f"    won / lost / drawn   "
          f"{fights['wins']:,} / {fights['losses']:,} / {fights['draws']:,}")
    print(f"    rounds           mean {fights['mean_rounds']}, "
          f"range {fights['shortest']}-{fights['longest']}")
    print()
    print("  outcomes")
    for name, count in list(report["outcomes"].items())[:22]:
        print(f"    {count:>7,}  {name}")
    if report["errors"]:
        print()
        print("  errors")
        for name, count in report["errors"].items():
            print(f"    {count:>7,}  {name}")
    print()
    for note in report["notes"]:
        print(f"  note: {note}")
    print()
    violations = report["violations"]
    if violations:
        print(f"  !! {len(violations)} INVARIANT VIOLATION(S)")
        for violation in violations[:20]:
            print(f"     [{violation['phase']}] {violation['invariant']}")
            print(f"       during {violation['action']}: {violation['detail']}")
    else:
        print("  no invariant violations")
    print("=" * 74)



# ==========================================================================
# Campaign: many independent simulations
# ==========================================================================


def _merge_counter(into: dict[str, int], other: Mapping[str, int]) -> None:
    for key, value in other.items():
        into[key] = into.get(key, 0) + value


def run_once(config: "RunConfig", content: Any) -> dict[str, Any]:
    """One complete, independent simulation. Fresh everything."""
    sandbox = build_sandbox(
        outage_rate=config.outage_rate,
        require_ownership=config.require_ownership,
        rate_capacity=400,
        rate_refill=400.0,
        session_ttl=timedelta(hours=2),
        opponent=config.opponent,
        max_users=config.max_users,
        content=content,
    )
    sim = Simulation(sandbox, seed=config.seed)
    players = build_players(sandbox, config.players, nfts=config.nfts, seed=config.seed)

    started = time.perf_counter()
    for name in config.phases:
        phase_start = time.perf_counter()
        if name == "lifecycle":
            sim.phase_lifecycle(players)
        elif name == "interrupted":
            sim.phase_interrupted(players[: min(len(players), 60)])
        elif name == "abuse":
            sim.phase_abuse(players)
        elif name == "outage":
            sim.phase_outage(players)
        elif name == "simultaneous":
            sim.phase_simultaneous(players)
        elif name == "concurrency":
            sim.phase_concurrency(
                players[: min(len(players), 120)], threads=config.threads
            )
        elif name == "soak":
            sim.phase_soak(players, steps=config.soak_steps)
        sim.metrics.phase_timing[name] = (
            sim.metrics.phase_timing.get(name, 0.0) + time.perf_counter() - phase_start
        )

    report = summarise(sim, players, time.perf_counter() - started)
    report["config"] = config.as_dict()
    return report


@dataclass(frozen=True)
class RunConfig:
    """One run's parameters. Varied across a campaign so no single shape hides a bug."""

    seed: int
    players: int
    nfts: int
    soak_steps: int
    threads: int
    outage_rate: float
    require_ownership: bool
    opponent: str
    max_users: int
    phases: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed, "players": self.players, "nfts": self.nfts,
            "soak_steps": self.soak_steps, "threads": self.threads,
            "outage_rate": self.outage_rate, "require_ownership": self.require_ownership,
            "opponent": self.opponent, "max_users": self.max_users,
            "phases": list(self.phases),
        }


def build_campaign(
    runs: int, *, base_seed: int, phases: tuple[str, ...], scale: float = 1.0
) -> list[RunConfig]:
    """Vary the shape of every run.

    A thousand runs of identical parameters is one run measured a thousand
    times. The point of a campaign is that the *shape* differs -- more players,
    fewer NFTs, a worse chain, ownership off, a different opponent -- so a bug
    that needs an unusual combination has a chance to appear.
    """
    rng = random.Random(base_seed)
    opponents = ("adaptive", "aggressive", "defensive", "random")
    configs = []
    for index in range(runs):
        players = max(6, int(rng.choice([8, 12, 20, 30, 45, 70]) * scale))
        configs.append(
            RunConfig(
                seed=base_seed + index * 7919,
                players=players,
                nfts=rng.choice([0, 1, 3, 6, 12]),
                soak_steps=max(50, int(rng.choice([200, 400, 800, 1500]) * scale)),
                threads=rng.choice([2, 4, 8]),
                # A quarter of runs face a chain that is materially unreliable.
                outage_rate=rng.choice([0.0, 0.0, 0.01, 0.05, 0.2, 0.4]),
                # Ownership off is a real deployment (the default one), so it
                # gets simulated rather than assumed equivalent.
                require_ownership=rng.random() > 0.25,
                opponent=rng.choice(opponents),
                # Sometimes far too small, to prove eviction is safe.
                max_users=rng.choice([25, 200, 5_000]),
                phases=phases,
            )
        )
    return configs


def run_campaign(configs: list[RunConfig], *, quiet: bool = False) -> dict[str, Any]:
    """Run every configuration and fold the results into one report."""
    content = load_content()
    started = time.perf_counter()

    total: dict[str, Any] = {
        "players": 0, "updates_handled": 0, "messages_checked": 0, "buttons_checked": 0,
    }
    actions: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    errors: dict[str, int] = {}
    chain: dict[str, int] = {}
    audit: dict[str, int] = {}
    arenas: dict[str, int] = {}
    histogram: dict[str, int] = {}
    fights = {
        "started": 0, "finished": 0, "abandoned": 0,
        "unfinished when the run ended": 0, "wins": 0, "losses": 0, "draws": 0,
    }
    peak_simultaneous = 0
    simultaneous_samples: list[float] = []
    notes: list[str] = []
    examples: dict[str, list[str]] = {}
    violations: list[dict[str, str]] = []
    phase_timing: dict[str, float] = {}
    run_rows: list[dict[str, Any]] = []
    clean_runs = 0
    round_lengths: list[tuple[int, int]] = []

    for index, config in enumerate(configs, start=1):
        report = run_once(config, content)
        for key in total:
            total[key] += report[key]
        _merge_counter(actions, report["actions"])
        _merge_counter(outcomes, report["outcomes"])
        _merge_counter(errors, report["errors"])
        _merge_counter(chain, report["chain"])
        _merge_counter(audit, report["audit_events"])
        _merge_counter(arenas, report["fights"]["by_arena"])
        for length, count in report["fights"]["round_histogram"].items():
            histogram[str(length)] = histogram.get(str(length), 0) + count
            round_lengths.append((int(length), count))
        for key in fights:
            fights[key] += report["fights"][key]
        peak_simultaneous = max(peak_simultaneous, report["fights"]["peak simultaneous (sampled)"])
        simultaneous_samples.append(report["fights"]["mean simultaneous (sampled)"])
        for key, value in report["phase_timing"].items():
            phase_timing[key] = phase_timing.get(key, 0.0) + value
        for key, values in report["examples"].items():
            examples.setdefault(key, [])
            for value in values:
                if len(examples[key]) < 4 and value not in examples[key]:
                    examples[key].append(value)
        if report["violations"]:
            for violation in report["violations"]:
                violation = dict(violation)
                violation["detail"] = f"[run {index}, seed {config.seed}] " + violation["detail"]
                violations.append(violation)
        else:
            clean_runs += 1
        for note in report["notes"]:
            notes.append(note)
        run_rows.append(
            {
                "run": index, "seed": config.seed, "players": config.players,
                "fights": report["fights"]["started"],
                "violations": len(report["violations"]),
            }
        )
        if not quiet and (index % 25 == 0 or index == len(configs)):
            print(
                f"    run {index}/{len(configs)}  "
                f"fights {fights['started']:,}  violations {len(violations)}",
                flush=True,
            )

    total_rounds = sum(count for _, count in round_lengths)
    mean_rounds = (
        sum(length * count for length, count in round_lengths) / total_rounds
        if total_rounds else 0.0
    )
    decided = fights["wins"] + fights["losses"] + fights["draws"]

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "runs": len(configs),
        "players": total["players"],
        "updates_handled": total["updates_handled"],
        "messages_checked": total["messages_checked"],
        "buttons_checked": total["buttons_checked"],
        "fights": {
            **fights,
            "peak simultaneous in one run (sampled)": peak_simultaneous,
            "mean simultaneous across runs (sampled)": round(
                sum(simultaneous_samples) / len(simultaneous_samples), 1
            ) if simultaneous_samples else 0,
            "mean_rounds": round(mean_rounds, 2),
            "longest": max((length for length, _ in round_lengths), default=0),
            "shortest": min((length for length, _ in round_lengths), default=0),
            "round_histogram": {
                k: histogram[k] for k in sorted(histogram, key=lambda x: int(x))
            },
            "by_arena": dict(sorted(arenas.items(), key=lambda kv: -kv[1])),
        },
        "actions": dict(sorted(actions.items(), key=lambda kv: -kv[1])),
        "outcomes": dict(sorted(outcomes.items(), key=lambda kv: -kv[1])),
        "errors": dict(sorted(errors.items(), key=lambda kv: -kv[1])),
        "chain": chain,
        "audit_events": dict(sorted(audit.items(), key=lambda kv: -kv[1])),
        "state": {},
        "phase_timing": {k: round(v, 2) for k, v in phase_timing.items()},
        "notes": [
            f"{text}  (x{count})" if count > 1 else text
            for text, count in Counter(notes).most_common(25)
        ],
        "examples": examples,
        "violations": violations,
        "per_run_summary": {
            "runs": len(configs),
            "runs with no violation": clean_runs,
            "runs with a violation": len(configs) - clean_runs,
            "fights per run (mean)": round(fights["started"] / max(1, len(configs)), 1),
            "player win rate": (
                f"{100 * fights['wins'] / decided:.1f}%" if decided else "n/a"
            ),
            "player loss rate": (
                f"{100 * fights['losses'] / decided:.1f}%" if decided else "n/a"
            ),
            "draw rate": (
                f"{100 * fights['draws'] / decided:.1f}%" if decided else "n/a"
            ),
        },
        "runs_detail": run_rows[:2000],
    }


# ==========================================================================
# Entry point
# ==========================================================================


def build_players(sandbox: Sandbox, count: int, *, nfts: int, seed: int) -> list[Player]:
    rng = RNG(seed)
    wallets = make_wallets(count)
    players = []
    for index, wallet in enumerate(wallets, start=1):
        # One wallet in seven is empty on purpose: a player with no NFTs is
        # a first-class case, not an edge one.
        holdings = 0 if (index % 7 == 0 or nfts <= 0) else rng.below(nfts) + 1
        if holdings:
            stock_wallet(sandbox.chain, wallet.address, holdings, rng)
        players.append(
            Player(
                user_id=1_000 + index,
                wallet=wallet,
                chat_id=1_000 + index,
                rng=random.Random(seed + index),
            )
        )
    return players


def main(argv: list[str] | None = None) -> int:
    # Outages, rejected logins and forged callbacks are the *subject* of this
    # run, and the code logs each one as it should. Printing thousands of
    # expected warnings would bury the report, so the log is quiet here and
    # the report is the record.
    logging.getLogger("rivalforge").setLevel(logging.CRITICAL)

    parser = argparse.ArgumentParser(description="Simulate the whole game.")
    parser.add_argument("--players", type=int, default=200)
    parser.add_argument("--nfts", type=int, default=6, help="max NFTs per wallet")
    parser.add_argument("--soak-steps", type=int, default=6_000)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20260907)
    parser.add_argument("--outage-rate", type=float, default=0.02)
    parser.add_argument(
        "--phase", action="append",
        choices=["lifecycle", "interrupted", "abuse", "outage", "simultaneous",
                 "concurrency", "soak"],
        help="run only these phases (repeatable)",
    )
    parser.add_argument(
        "--runs", type=int, default=1,
        help="run this many independent simulations and aggregate them",
    )
    parser.add_argument(
        "--scale", type=float, default=1.0,
        help="scale the per-run size in campaign mode",
    )
    parser.add_argument("--json", help="write the full report here")
    parser.add_argument("--html", help="write an HTML report here")
    args = parser.parse_args(argv)

    phases = tuple(args.phase or [
        "lifecycle", "interrupted", "abuse", "outage", "simultaneous",
        "concurrency", "soak",
    ])

    if args.runs > 1:
        configs = build_campaign(
            args.runs, base_seed=args.seed, phases=phases, scale=args.scale
        )
        print(f"  campaign: {args.runs:,} independent simulations", flush=True)
        report = run_campaign(configs)
        print_report(report)
        if args.json:
            Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"  wrote {args.json}")
        if args.html:
            from simreport import write_html  # noqa: PLC0415

            write_html(report, Path(args.html))
            print(f"  wrote {args.html}")
        return 1 if report["violations"] else 0

    content = load_content()
    sandbox = build_sandbox(
        outage_rate=args.outage_rate,
        rate_capacity=400,
        rate_refill=400.0,
        session_ttl=timedelta(hours=2),
        content=content,
    )
    sim = Simulation(sandbox, seed=args.seed)
    players = build_players(sandbox, args.players, nfts=args.nfts, seed=args.seed)

    started = time.perf_counter()

    for name in phases:
        phase_start = time.perf_counter()
        print(f"  running phase: {name} ...", flush=True)
        if name == "lifecycle":
            sim.phase_lifecycle(players)
        elif name == "interrupted":
            sim.phase_interrupted(players[: min(len(players), 60)])
        elif name == "abuse":
            sim.phase_abuse(players)
        elif name == "outage":
            sim.phase_outage(players)
        elif name == "simultaneous":
            sim.phase_simultaneous(players)
        elif name == "concurrency":
            sim.phase_concurrency(players[: min(len(players), 120)], threads=args.threads)
        elif name == "soak":
            sim.phase_soak(players, steps=args.soak_steps)
        sim.metrics.phase_timing[name] = time.perf_counter() - phase_start

    elapsed = time.perf_counter() - started
    report = summarise(sim, players, elapsed)
    print_report(report)

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")
    if args.html:
        from simreport import write_html  # noqa: PLC0415

        write_html(report, Path(args.html))
        print(f"  wrote {args.html}")

    return 1 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
