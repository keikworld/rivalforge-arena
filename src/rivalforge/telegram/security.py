"""Security primitives for the Telegram surface.

Telegram is the first place this game accepts input from strangers, so every
value arriving from it is hostile until proven otherwise.

## The four things that go wrong

1.  **Formatting injection.** Telegram renders MarkdownV2 and HTML. NFT names
    come from on-chain metadata, which *anyone* can write -- minting a token
    called ``*bold* [click](https://evil.example)`` costs a few cents. Rendering
    that unescaped turns another player's roster into a phishing link. Every
    piece of text that did not originate in this repository is escaped.

2.  **Forged and replayed callbacks.** `callback_data` makes a round trip
    through the user's client, so it is user input no matter how it was
    generated. Without binding, a player can craft a callback naming another
    player's match, or replay yesterday's. Payloads are HMAC-signed and bound
    to the Telegram user id.

3.  **The wrong chat.** A wallet challenge posted in a group is a challenge
    every member can see. Sensitive flows are private-chat only.

4.  **Flooding.** A bot endpoint is reachable by anyone who finds it. Every
    update passes a per-user token bucket before any work happens.

## What we deliberately do not store

Telegram hands us a display name, a username, a language code and a chat id on
every update. We keep only the numeric user id, and only for as long as a
session lasts. A username is a real identity in a way a wallet address is not.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Final, Mapping

from ..security.validation import validate_int

logger = logging.getLogger(__name__)

__all__ = [
    "escape_markdown",
    "escape_html",
    "CallbackSigner",
    "CallbackError",
    "RateLimiter",
    "RateLimited",
    "validate_user_id",
    "validate_chat_id",
    "require_private_chat",
    "WrongChatType",
    "MAX_CALLBACK_BYTES",
    "safe_name",
    "clean_text",
    "escape_code",
]

#: Telegram's hard limit on callback_data. Exceeding it makes the button fail
#: silently at send time, which is a maddening bug to chase.
MAX_CALLBACK_BYTES: Final = 64

#: Every character MarkdownV2 treats as syntax. Missing one is a rendering bug
#: at best and a clickable link at worst.
_MARKDOWN_V2_SPECIALS: Final = r"_*[]()~`>#+-=|{}.!\\"
_MARKDOWN_ESCAPE = re.compile(f"([{re.escape(_MARKDOWN_V2_SPECIALS)}])")

#: Telegram ids are int64. Anything outside that is not an id.
_MAX_TELEGRAM_ID: Final = 2**63 - 1

#: How much attacker-controlled text we will render at all.
MAX_RENDERED_NAME: Final = 40


class CallbackError(Exception):
    """A callback payload was missing, malformed, forged, or not this user's."""


class RateLimited(Exception):
    """The user is sending updates faster than the bucket refills."""


class WrongChatType(Exception):
    """A sensitive flow was attempted somewhere it must not be."""


# --------------------------------------------------------------------------
# Escaping
# --------------------------------------------------------------------------


def escape_markdown(text: object) -> str:
    """Escape text for Telegram MarkdownV2.

    Applied to *everything* that did not originate in this repository: display
    names, NFT names, collection names, error text echoed back.

    Minting an NFT named ``[Claim your airdrop](https://evil.example)`` costs
    a few cents, and rendering it unescaped in a roster is a phishing link with
    our bot's name on it.
    """
    return _MARKDOWN_ESCAPE.sub(r"\\\1", str(text))


def escape_html(text: object) -> str:
    """Escape text for Telegram's HTML parse mode."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def escape_code(text: object) -> str:
    """Escape text for the inside of a MarkdownV2 ``pre`` or ``code`` entity.

    Only two characters are syntax in there, and escaping exactly those is
    what keeps a fenced block from being closed early by its own contents.

    Most of this bot's output is a fenced block: the game is made of aligned
    bars and columns, monospace is how they read, and a block with a
    two-character escape surface is a far smaller target than free-form
    MarkdownV2 with sixteen.
    """
    return str(text).replace("\\", "\\\\").replace("`", "\\`")


def clean_text(text: object, *, limit: int = MAX_RENDERED_NAME) -> str:
    """Bound and strip a piece of attacker-controlled text, without escaping.

    Two steps, both necessary before the text reaches anyone:

    * control and format characters are removed -- a zero-width joiner or a
      right-to-left override can make one name render as another, and a
      newline inside an NFT name breaks a table apart;
    * the result is truncated, because a 4,000-character NFT name is a way to
      push the rest of a message off the screen.

    The caller escapes for whichever context it is rendering into. Splitting
    the two means the code-block path does not have to un-escape MarkdownV2 to
    avoid showing backslashes to the player.
    """
    raw = str(text)
    stripped = "".join(
        ch for ch in raw
        if ch.isprintable() and ch not in "​‌‍‪‫‬‭‮"
    ).strip()
    if not stripped:
        return "(unnamed)"
    if len(stripped) > limit:
        stripped = stripped[: limit - 1] + "…"
    return stripped


def safe_name(text: object, *, limit: int = MAX_RENDERED_NAME) -> str:
    """`clean_text`, then MarkdownV2-escaped. For text outside a code block."""
    return escape_markdown(clean_text(text, limit=limit))


# --------------------------------------------------------------------------
# Identifiers
# --------------------------------------------------------------------------


def validate_user_id(value: object, *, field: str = "user_id") -> int:
    """Validate a Telegram user id."""
    return validate_int(value, field=field, minimum=1, maximum=_MAX_TELEGRAM_ID)


def validate_chat_id(value: object, *, field: str = "chat_id") -> int:
    """Validate a Telegram chat id. Group ids are negative, so the range is wider."""
    return validate_int(value, field=field, minimum=-_MAX_TELEGRAM_ID, maximum=_MAX_TELEGRAM_ID)


def require_private_chat(chat: Mapping[str, Any]) -> int:
    """Assert this is a one-to-one chat, and return its id.

    Wallet connection, session tokens and anything else a bystander should not
    see are private-only. A challenge posted in a group is a challenge every
    member can read and, worse, one any of them could try to answer.

    Raises:
        WrongChatType: if the chat is a group, supergroup or channel.
    """
    if not isinstance(chat, Mapping):
        raise WrongChatType("no chat on this update")
    kind = chat.get("type")
    if kind != "private":
        raise WrongChatType(
            "that only works in a direct message with the bot, not in a group"
        )
    return validate_chat_id(chat.get("id"))


# --------------------------------------------------------------------------
# Callback signing
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Callback:
    """A verified callback payload."""

    action: str
    argument: str
    user_id: int


class CallbackSigner:
    """Signs and verifies `callback_data`, bound to one user.

    `callback_data` travels to the user's client and comes back, so it is user
    input however it was produced. A player can send any string a button could
    have contained -- including one they saw in someone else's chat.

    The payload is therefore HMAC-signed over the action, the argument *and the
    user id*, so a callback lifted from another chat fails verification rather
    than acting on that user's behalf.

    The 64-byte ceiling is tight, so the signature is truncated to 10 bytes
    (80 bits). That is not a key -- it is a per-user MAC over a short-lived,
    low-value action, where the attacker gets no oracle and each attempt costs
    a round trip. 80 bits is ample; the alternative is buttons that do not fit.
    """

    __slots__ = ("_key", "_digest_bytes")

    #: 16 base32 characters. Fits alongside a short action and argument.
    SIGNATURE_CHARS: Final = 16

    def __init__(self, key: bytes | None = None) -> None:
        # A random key per process when none is supplied: callbacks then stop
        # working across a restart, which is a mild annoyance and strictly
        # safer than a hard-coded default nobody changes.
        self._key = key or secrets.token_bytes(32)
        if len(self._key) < 16:
            raise ValueError("callback signing key must be at least 16 bytes")

    def _signature(self, action: str, argument: str, user_id: int) -> str:
        message = f"{action}|{argument}|{user_id}".encode("utf-8")
        digest = hmac.new(self._key, message, hashlib.sha256).digest()
        # base32 keeps it alphanumeric, so it cannot collide with the separator.
        import base64  # noqa: PLC0415

        return base64.b32encode(digest).decode("ascii")[: self.SIGNATURE_CHARS]

    def sign(self, action: str, argument: str, user_id: int) -> str:
        """Build signed callback_data.

        Raises:
            ValueError: if the result would exceed Telegram's 64-byte limit --
                loudly, because the alternative is a button that silently fails
                to send.
        """
        if "|" in action or "|" in argument:
            raise ValueError("action and argument must not contain '|'")
        validate_user_id(user_id)
        payload = f"{action}|{argument}|{self._signature(action, argument, user_id)}"
        encoded = payload.encode("utf-8")
        if len(encoded) > MAX_CALLBACK_BYTES:
            raise ValueError(
                f"callback_data is {len(encoded)} bytes, over Telegram's "
                f"{MAX_CALLBACK_BYTES}-byte limit"
            )
        return payload

    def verify(self, data: object, user_id: int) -> Callback:
        """Verify callback_data came from a button we made for *this* user.

        Raises:
            CallbackError: for anything malformed, forged, or belonging to
                another user. One message for all of them -- the difference is
                an oracle and the caller cannot act on it anyway.
        """
        if not isinstance(data, str) or not data:
            raise CallbackError("missing callback data")
        if len(data.encode("utf-8")) > MAX_CALLBACK_BYTES:
            raise CallbackError("oversized callback data")

        parts = data.split("|")
        if len(parts) != 3:
            raise CallbackError("malformed callback data")
        action, argument, signature = parts

        expected = self._signature(action, argument, user_id)
        # Constant-time: a timing side channel here would let someone recover
        # a valid signature byte by byte.
        if not hmac.compare_digest(signature, expected):
            raise CallbackError("callback signature does not match")

        return Callback(action=action, argument=argument, user_id=user_id)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


class RateLimiter:
    """A per-user token bucket.

    Checked before any work happens on an update, because the expensive parts
    -- an RPC call, a database write -- are exactly what a flood would target.

    Bounded in the number of users it tracks, so the limiter itself cannot be
    turned into the memory-exhaustion vector.
    """

    __slots__ = ("_capacity", "_refill_per_second", "_buckets", "_lock", "_max_users")

    def __init__(
        self,
        *,
        capacity: int = 20,
        refill_per_second: float = 1.0,
        max_users: int = 50_000,
    ) -> None:
        if capacity < 1 or refill_per_second <= 0 or max_users < 1:
            raise ValueError("capacity, refill rate and max_users must be positive")
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._max_users = max_users
        self._buckets: dict[int, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, user_id: int, *, now: float | None = None) -> None:
        """Consume one token for `user_id`.

        Raises:
            RateLimited: if the bucket is empty.
        """
        moment = time.monotonic() if now is None else now
        with self._lock:
            if len(self._buckets) >= self._max_users:
                self._evict_stale(moment)

            tokens, last_seen = self._buckets.get(user_id, (float(self._capacity), moment))
            tokens = min(
                float(self._capacity),
                tokens + (moment - last_seen) * self._refill_per_second,
            )
            if tokens < 1.0:
                self._buckets[user_id] = (tokens, moment)
                raise RateLimited("too many requests; slow down for a moment")
            self._buckets[user_id] = (tokens - 1.0, moment)

    def _evict_stale(self, now: float) -> None:
        """Drop buckets that have refilled completely -- they carry no state."""
        full_after = self._capacity / self._refill_per_second
        stale = [uid for uid, (_, seen) in self._buckets.items() if now - seen > full_after]
        for uid in stale:
            del self._buckets[uid]
        if not stale and self._buckets:
            # Everyone is active. Drop the least recently seen rather than
            # refusing to serve anyone new.
            oldest = min(self._buckets.items(), key=lambda kv: kv[1][1])[0]
            del self._buckets[oldest]

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)
