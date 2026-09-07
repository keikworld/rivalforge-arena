"""The long-poll loop: the only part of the Telegram surface that does I/O.

Everything the bot decides happens in `handlers.py` and returns a list of
actions. This module's whole job is to fetch updates, hand each one to the
handlers, and perform what comes back. Keeping it that thin is what makes the
interesting behaviour testable without a socket.

## Three things a loop like this gets wrong

**A poison update jams it forever.** Telegram redelivers every update until it
is acknowledged, and acknowledgement is a side effect of asking for the *next*
offset. So the offset advances even when handling an update raised -- otherwise
one malformed message stops the bot for everyone, permanently, and anyone can
send one.

**It dies on a blip.** A timeout or a 502 is normal. Transient failures back
off and retry; only a permanent one (a revoked token) stops the loop, and it
says which.

**It cannot be stopped cleanly.** SIGINT and SIGTERM set a flag that the loop
checks between polls, so a container restart finishes the update in hand rather
than being killed mid-write.

Long polling rather than a webhook, deliberately: a webhook needs a public
HTTPS endpoint, which is a listening socket on the internet and the largest
piece of attack surface this project would own. Polling has none -- the bot
makes outbound connections only, and there is nothing to find and nothing to
scan.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from typing import Any, Final, Mapping, Sequence

from ..plugins.resilience import PermanentError, TransientError
from ..security.redaction import install_redaction
from .api import TelegramAPI
from .handlers import AnswerCallback, BotHandlers, EditMessage, SendMessage

logger = logging.getLogger(__name__)

__all__ = ["Bot", "run_forever"]

#: How long to wait after a transient failure, doubling to the ceiling.
_BACKOFF_START: Final = 1.0
_BACKOFF_MAX: Final = 60.0

#: Give up after this many transient failures in a row. A loop that retries
#: forever against a dead endpoint is a loop that never tells anyone.
_MAX_CONSECUTIVE_FAILURES: Final = 20


class Bot:
    """Polls Telegram and performs what the handlers decide."""

    __slots__ = ("_api", "_handlers", "_offset", "_stopping", "_poll_seconds", "_sleep")

    def __init__(
        self,
        api: TelegramAPI,
        handlers: BotHandlers,
        *,
        poll_seconds: int = 25,
        sleep: Any = time.sleep,
    ) -> None:
        self._api = api
        self._handlers = handlers
        self._offset: int | None = None
        self._stopping = threading.Event()
        self._poll_seconds = int(poll_seconds)
        # Injected so tests do not actually wait out a backoff.
        self._sleep = sleep

    # -- lifecycle --------------------------------------------------------

    def stop(self) -> None:
        """Ask the loop to finish after the update in hand."""
        self._stopping.set()

    @property
    def stopping(self) -> bool:
        return self._stopping.is_set()

    def start(self) -> Mapping[str, Any]:
        """Prove the token works and clear any leftover webhook."""
        identity = self._api.get_me()
        # A webhook left over from another deployment silently swallows every
        # update, and `getUpdates` then returns nothing forever with no error.
        self._api.delete_webhook()
        return identity

    # -- the loop ---------------------------------------------------------

    def poll_once(self) -> int:
        """One poll. Returns how many updates were handled.

        Raises:
            TransientError, PermanentError: passed through for the loop to
                classify. Handling an update never raises -- `handle()` catches
                its own failures -- so anything reaching here is transport.
        """
        updates = self._api.get_updates(self._offset, poll_seconds=self._poll_seconds)
        handled = 0
        for update in updates:
            update_id = update.get("update_id")
            if isinstance(update_id, int):
                # Advance first. Telegram redelivers anything below the offset,
                # so an update that makes us fail must not be asked for again.
                self._offset = update_id + 1
            try:
                self._perform(self._handlers.handle(update))
            except PermanentError:
                raise
            except Exception:
                # One player's failed reply must not stop the others' matches.
                logger.exception("could not deliver a reply")
            handled += 1
        return handled

    def _perform(self, actions: Sequence[Any]) -> None:
        for action in actions:
            if isinstance(action, SendMessage):
                self._api.send_message(action.chat_id, action.text, keyboard=action.keyboard)
            elif isinstance(action, EditMessage):
                self._api.edit_message_text(
                    action.chat_id, action.message_id, action.text, keyboard=action.keyboard
                )
            elif isinstance(action, AnswerCallback):
                self._api.answer_callback_query(
                    action.callback_id, text=action.text, alert=action.alert
                )
            else:  # pragma: no cover - the action union is closed
                logger.error("unknown action %r", type(action).__name__)

    def run(self) -> int:
        """Poll until stopped. Returns a process exit code."""
        backoff = _BACKOFF_START
        failures = 0

        while not self._stopping.is_set():
            try:
                self.poll_once()
            except PermanentError as exc:
                # A revoked token, a malformed request: retrying cannot help.
                logger.error("stopping: %s", exc)
                return 1
            except TransientError as exc:
                failures += 1
                if failures >= _MAX_CONSECUTIVE_FAILURES:
                    logger.error("giving up after %d consecutive failures: %s", failures, exc)
                    return 1
                logger.warning("poll failed (%s); retrying in %.0fs", exc, backoff)
                self._sleep(backoff)
                backoff = min(_BACKOFF_MAX, backoff * 2)
                continue
            except KeyboardInterrupt:
                self.stop()
                break
            failures = 0
            backoff = _BACKOFF_START

        logger.info("stopped cleanly")
        return 0


def run_forever(
    api: TelegramAPI,
    handlers: BotHandlers,
    *,
    poll_seconds: int = 25,
    install_signal_handlers: bool = True,
) -> int:
    """Start a bot, wire signals to a clean shutdown, and run it."""
    install_redaction()
    bot = Bot(api, handlers, poll_seconds=poll_seconds)

    if install_signal_handlers:
        def _on_signal(signum, _frame):  # pragma: no cover - signal delivery
            logger.info("received signal %s; finishing the current update", signum)
            bot.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):  # pragma: no cover - not the main thread
                logger.debug("could not install a handler for %s", sig)

    try:
        identity = bot.start()
    except PermanentError as exc:
        # Almost always a wrong or revoked token. It must reach the operator as
        # one readable line: a traceback here is both unhelpful and a place the
        # request URL -- which carries the token -- can escape, since redaction
        # covers logging and not an unhandled stack trace.
        logger.error("could not start: %s", exc)
        return 1
    except TransientError as exc:
        logger.error("could not reach the Bot API: %s", exc)
        return 1

    username = identity.get("username")
    logger.info("connected as @%s", username if isinstance(username, str) else "unknown")
    return bot.run()
