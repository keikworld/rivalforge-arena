"""A minimal Telegram Bot API client.

`urllib` and the standard library, in the same spirit as `DasWalletProvider`:
this makes a handful of HTTPS POSTs with a JSON body, which does not justify
the supply-chain surface of a bot framework. The engine has no runtime
dependencies and the surfaces around it should stay close to that.

The transport is injected, so every test in this package runs against a fake
and none of them touch the network.

## What this client is careful about

**The token is the bot.** Whoever holds it can read every message sent to the
bot and post as it. So it comes from the environment only -- never a CLI
argument, which is visible in `ps` -- it never appears in a log line or an
exception message, and the URL that carries it is redacted before it is
formatted into anything.

**Responses are untrusted.** An API response is parsed defensively and read
with a hard byte ceiling: a client that reads an unbounded body has handed
whoever controls the endpoint a way to exhaust its memory.

**Failures are typed.** Transient (timeout, 5xx, 429) and permanent (a 400 we
will keep getting) are distinguished, so the retry layer only retries what can
succeed on a second attempt.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final, Mapping, Sequence

from ..plugins.resilience import (
    CircuitBreaker,
    PermanentError,
    RetryPolicy,
    TransientError,
    call_with_retries,
)
from ..security.validation import ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "TelegramAPI",
    "TelegramError",
    "TOKEN_ENV_VARS",
    "read_token",
    "redact_token",
]

#: Where the token may come from. Environment only, in this order.
TOKEN_ENV_VARS: Final = ("RIVALFORGE_TELEGRAM_TOKEN", "TELEGRAM_BOT_TOKEN")

#: `<bot id>:<secret>`. Checked before the first request so a truncated or
#: quote-wrapped token fails at start-up with a clear message rather than as a
#: 404 from Telegram half an hour later.
_TOKEN_SHAPE: Final = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")

#: Ceiling on a single response body. `getUpdates` with a full batch of long
#: messages is far below this; anything above it is not a Telegram response.
MAX_RESPONSE_BYTES: Final = 4 * 1024 * 1024

#: Telegram's own message ceiling. Longer text is rejected by the API, so it is
#: caught here where the message can say which text was too long.
MAX_MESSAGE_CHARS: Final = 4096

#: The only update kinds this bot handles. Declared to Telegram so it does not
#: send the rest at all -- there is no handler for a channel post, and the
#: cheapest way to not mishandle an update is to not receive it.
ALLOWED_UPDATES: Final = ("message", "callback_query")


class TelegramError(RuntimeError):
    """The Bot API rejected a call, or answered with something unusable."""


def redact_token(text: str) -> str:
    """Replace a bot token with its public half wherever it appears."""
    return _TOKEN_IN_TEXT.sub(r"\1:[redacted]", text)


_TOKEN_IN_TEXT: Final = re.compile(r"(?<!\d)(\d{6,12}):[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")


def read_token(env: Mapping[str, str] | None = None) -> str:
    """Read and validate the bot token from the environment.

    Raises:
        ValidationError: if no token is set, or it is not shaped like one. The
            message never contains the value.
    """
    environment = os.environ if env is None else env
    for name in TOKEN_ENV_VARS:
        raw = environment.get(name)
        if raw:
            token = raw.strip()
            if not _TOKEN_SHAPE.match(token):
                raise ValidationError(
                    name,
                    "does not look like a Telegram bot token "
                    "(expected '<bot id>:<secret>'); check for stray quotes or whitespace",
                )
            return token
    raise ValidationError(
        TOKEN_ENV_VARS[0],
        f"no bot token set; export one of {' or '.join(TOKEN_ENV_VARS)}",
    )


class TelegramAPI:
    """The subset of the Bot API this game uses.

    Six methods. A bot that can only do these six things is a bot whose blast
    radius is those six things if its token leaks -- which is a weaker
    guarantee than not leaking it, and worth having anyway.
    """

    BASE_URL: Final = "https://api.telegram.org"
    #: A poll waits this long server-side before answering with nothing.
    DEFAULT_POLL_SECONDS: Final = 25
    #: Read timeout for a normal call. Long polls add their own wait on top.
    DEFAULT_TIMEOUT: Final = 10.0

    __slots__ = ("_token", "_base", "_timeout", "_policy", "_breaker", "_opener")

    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float | None = None,
        policy: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        opener: Any = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        self._token = token if token is not None else read_token(env)
        if not _TOKEN_SHAPE.match(self._token):
            raise ValidationError("token", "does not look like a Telegram bot token")

        self._base = (base_url or self.BASE_URL).rstrip("/")
        # A plain-HTTP base would put the token on the wire in clear text. The
        # exception is a loopback address, which is how the tests and a local
        # mock server work.
        if not self._base.startswith("https://") and not _is_loopback(self._base):
            raise ValidationError("base_url", "the Bot API must be reached over HTTPS")

        self._timeout = self.DEFAULT_TIMEOUT if timeout is None else float(timeout)
        self._policy = policy or RetryPolicy(attempts=3, total_timeout=30.0)
        self._breaker = breaker or CircuitBreaker("telegram", threshold=8, cooldown=20.0)
        self._opener = opener or urllib.request.urlopen

    # -- transport --------------------------------------------------------

    def _url(self, method: str) -> str:
        return f"{self._base}/bot{self._token}/{method}"

    def _call(self, method: str, payload: Mapping[str, Any], *, timeout: float) -> Any:
        """One Bot API call. Returns the `result` field.

        Raises:
            TransientError: worth another attempt.
            PermanentError: not worth another attempt.
        """
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._url(method),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with self._opener(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise _from_http_error(method, exc) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # `exc` can carry the request URL, and the URL carries the token.
            raise TransientError(
                f"could not reach the Bot API for {method}: {redact_token(str(exc))}"
            ) from None

        if len(raw) > MAX_RESPONSE_BYTES:
            raise PermanentError(f"{method} returned an oversized response")

        try:
            payload_out = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TransientError(f"{method} returned a malformed response") from None

        if not isinstance(payload_out, dict):
            raise TransientError(f"{method} returned an unexpected payload")
        if not payload_out.get("ok"):
            # `description` is written by Telegram, not by a player, but it can
            # echo request content -- so it is redacted before it is logged.
            description = redact_token(str(payload_out.get("description", "no reason given")))
            raise PermanentError(f"{method} was rejected: {description}")
        return payload_out.get("result")

    def _request(
        self, method: str, payload: Mapping[str, Any], *, timeout: float | None = None
    ) -> Any:
        return call_with_retries(
            lambda: self._call(method, payload, timeout=timeout or self._timeout),
            policy=self._policy,
            breaker=self._breaker,
            description=f"telegram.{method}",
        )

    # -- the six methods --------------------------------------------------

    def get_me(self) -> Mapping[str, Any]:
        """Identify the bot. Used at start-up to prove the token works."""
        result = self._request("getMe", {})
        return result if isinstance(result, Mapping) else {}

    def delete_webhook(self) -> None:
        """Drop any webhook so long polling can take over.

        A webhook left over from another deployment silently swallows every
        update, and `getUpdates` then returns nothing forever with no error.
        """
        self._request("deleteWebhook", {"drop_pending_updates": False})

    def get_updates(
        self, offset: int | None = None, *, poll_seconds: int | None = None
    ) -> Sequence[Mapping[str, Any]]:
        """Long-poll for updates.

        The read timeout is the server-side wait plus a margin: timing out
        before Telegram answers turns every quiet minute into a spurious error.
        """
        wait = self.DEFAULT_POLL_SECONDS if poll_seconds is None else int(poll_seconds)
        payload: dict[str, Any] = {
            "timeout": wait,
            "allowed_updates": list(ALLOWED_UPDATES),
            "limit": 50,
        }
        if offset is not None:
            payload["offset"] = int(offset)
        result = self._request("getUpdates", payload, timeout=self._timeout + wait)
        if not isinstance(result, list):
            return ()
        return [item for item in result if isinstance(item, Mapping)]

    def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        keyboard: Sequence[Sequence[Mapping[str, str]]] | None = None,
        parse_mode: str = "MarkdownV2",
    ) -> Mapping[str, Any]:
        """Send a message.

        Link previews are always off. A preview is an outbound fetch of a URL
        that appeared in a message, and messages carry NFT names that anyone
        can write.
        """
        if len(text) > MAX_MESSAGE_CHARS:
            raise TelegramError(
                f"message is {len(text)} characters, over Telegram's {MAX_MESSAGE_CHARS} limit"
            )
        payload: dict[str, Any] = {
            "chat_id": int(chat_id),
            "text": text,
            "parse_mode": parse_mode,
            "link_preview_options": {"is_disabled": True},
        }
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": [list(row) for row in keyboard]}
        result = self._request("sendMessage", payload)
        return result if isinstance(result, Mapping) else {}

    def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        *,
        keyboard: Sequence[Sequence[Mapping[str, str]]] | None = None,
        parse_mode: str = "MarkdownV2",
    ) -> None:
        """Replace a message's text, so a match updates in place."""
        if len(text) > MAX_MESSAGE_CHARS:
            raise TelegramError(
                f"message is {len(text)} characters, over Telegram's {MAX_MESSAGE_CHARS} limit"
            )
        payload: dict[str, Any] = {
            "chat_id": int(chat_id),
            "message_id": int(message_id),
            "text": text,
            "parse_mode": parse_mode,
            "link_preview_options": {"is_disabled": True},
        }
        payload["reply_markup"] = {
            "inline_keyboard": [list(row) for row in keyboard] if keyboard else []
        }
        try:
            self._request("editMessageText", payload)
        except PermanentError as exc:
            # Editing a message to the text it already has is an error in the
            # Bot API and a no-op everywhere else. It is not worth surfacing.
            if "not modified" not in str(exc).lower():
                raise

    def answer_callback_query(
        self, callback_id: str, *, text: str = "", alert: bool = False
    ) -> None:
        """Acknowledge a button press.

        Telegram shows a spinner on the button until this is sent, so it is
        sent even when the press was rejected -- a silent refusal reads as the
        bot being broken.
        """
        payload: dict[str, Any] = {"callback_query_id": str(callback_id)}
        if text:
            # Telegram caps this at 200 characters and rejects the call above it.
            payload["text"] = text[:200]
            payload["show_alert"] = bool(alert)
        try:
            self._request("answerCallbackQuery", payload)
        except PermanentError:
            # A callback id expires after about a minute. Losing the race is
            # normal and the user has already had their reply.
            logger.debug("callback acknowledgement was too late")


def _is_loopback(base_url: str) -> bool:
    host = urllib.parse.urlsplit(base_url).hostname or ""
    return host in ("127.0.0.1", "::1", "localhost")


def _from_http_error(method: str, exc: urllib.error.HTTPError) -> Exception:
    """Classify an HTTP failure. 429 and 5xx can succeed on a retry; 4xx cannot."""
    if exc.code == 429 or exc.code >= 500:
        return TransientError(f"{method} got HTTP {exc.code} from the Bot API")
    if exc.code in (401, 403):
        # Worth its own message: this is almost always a revoked or wrong token,
        # and "HTTP 401" alone sends people looking in the wrong place.
        return PermanentError(
            f"{method} was refused (HTTP {exc.code}); the bot token is wrong or revoked"
        )
    return PermanentError(f"{method} got HTTP {exc.code} from the Bot API")
