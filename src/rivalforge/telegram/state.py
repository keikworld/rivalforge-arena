"""Per-user conversation state, deliberately small and deliberately bounded.

A chat bot has to remember something between messages: which match you are in,
which challenge you were asked to sign, whether you armed a soul. That memory
is an attack surface twice over -- it is unbounded growth if nobody caps it,
and it is a place secrets accumulate if nobody says what may live there.

So this module states both rules in code:

**Bounded.** A fixed ceiling on tracked users, with idle sessions evicted
first. Anyone can start a conversation with a public bot, so "one dictionary
entry per user who ever said hello" is a memory-exhaustion vector with a
Telegram account as its only cost.

**Minimal.** Keyed by the numeric Telegram user id and nothing else. No
username, no display name, no chat history. What we keep is what the next
message cannot work without.

State lives in this process, so a restart ends every match in progress and
every player has to reconnect. That is a real cost and it is the right trade
for now: the alternative is writing session tokens and half-finished matches
to a database, and a durable copy of a bearer token is a worse thing to own
than a lost match.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Final

logger = logging.getLogger(__name__)

__all__ = ["UserState", "StateStore", "DEFAULT_IDLE_SECONDS", "DEFAULT_MAX_USERS"]

#: How long a conversation may sit untouched before it is dropped.
DEFAULT_IDLE_SECONDS: Final = 30 * 60
#: How many conversations to track at once.
DEFAULT_MAX_USERS: Final = 10_000


@dataclass
class UserState:
    """Everything the bot remembers about one player, between messages.

    `session_token` is a bearer credential: whoever has it is that wallet for
    as long as it lives. It stays in memory, is never logged, and is dropped
    the moment the conversation is evicted.
    """

    user_id: int
    #: A live wallet session, if they have connected one.
    session_token: str | None = None
    #: The wallet behind that session. Kept alongside the token so the bot can
    #: say who you are without resolving the token on every message.
    wallet: str | None = None
    #: The nonce of the challenge they were last asked to sign. One at a time:
    #: a second `/connect` replaces the first, so an old challenge cannot be
    #: answered later.
    pending_nonce: str | None = None
    #: The mint they have chosen to fight with, once ownership was proven.
    chosen_mint: str | None = None
    #: Its display name, already cleaned at the roster boundary. Kept so the
    #: fighter is called what the player picked, not what the mint hashes to.
    chosen_name: str | None = None
    #: The match in progress, if any. An opaque object to this module -- state
    #: storage has no business knowing the rules.
    match: Any = None
    #: Fixed context for the match in progress.
    match_context: dict[str, Any] = field(default_factory=dict)
    #: Whether the next stance will also spend a soul.
    soul_armed: bool = False
    last_seen: float = 0.0

    def end_match(self) -> None:
        self.match = None
        self.match_context = {}
        self.soul_armed = False


class StateStore:
    """A bounded, self-evicting map of user id to `UserState`.

    Thread-safe: the long-poll loop is single-threaded today, but a future
    webhook front end is not, and a store that quietly assumed otherwise would
    be a race nobody thinks to look for.
    """

    __slots__ = ("_states", "_lock", "_max_users", "_idle_seconds")

    def __init__(
        self,
        *,
        max_users: int = DEFAULT_MAX_USERS,
        idle_seconds: float = DEFAULT_IDLE_SECONDS,
    ) -> None:
        if max_users < 1 or idle_seconds <= 0:
            raise ValueError("max_users and idle_seconds must be positive")
        self._states: dict[int, UserState] = {}
        self._lock = threading.Lock()
        self._max_users = max_users
        self._idle_seconds = float(idle_seconds)

    def get(self, user_id: int, *, now: float | None = None) -> UserState:
        """The state for `user_id`, created on first use."""
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._expire(moment)
            state = self._states.get(user_id)
            if state is None:
                if len(self._states) >= self._max_users:
                    self._evict_oldest()
                state = UserState(user_id=user_id)
                self._states[user_id] = state
            state.last_seen = moment
            return state

    def forget(self, user_id: int) -> None:
        """Drop everything about one user. What `/disconnect` calls."""
        with self._lock:
            self._states.pop(user_id, None)

    def _expire(self, now: float) -> None:
        stale = [uid for uid, s in self._states.items() if now - s.last_seen > self._idle_seconds]
        for uid in stale:
            del self._states[uid]
        if stale:
            logger.debug("dropped %d idle conversation(s)", len(stale))

    def _evict_oldest(self) -> None:
        if not self._states:
            return
        oldest = min(self._states.items(), key=lambda kv: kv[1].last_seen)[0]
        del self._states[oldest]
        logger.info("conversation store is full; dropped the least recently active")

    def __len__(self) -> int:
        with self._lock:
            return len(self._states)
