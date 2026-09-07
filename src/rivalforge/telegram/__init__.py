"""The Telegram surface: the first place this game meets strangers.

Four modules, in the order an update passes through them:

* `security` -- escaping, callback signing, chat-type and rate checks;
* `api`      -- a minimal Bot API client over `urllib`, transport injected;
* `handlers` -- every command and button, returning actions rather than doing
  I/O, so each one is a dictionary in and a list out;
* `bot`      -- the long-poll loop, the only part that touches a socket.

`state` holds the small, bounded amount the bot remembers between messages.

Nothing here is imported by the game core. Deleting this package would leave a
working game, which is the test that the layering is real.
"""

from __future__ import annotations

__all__ = ["security", "api", "render", "state", "handlers", "bot"]
