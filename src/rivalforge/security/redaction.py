"""Redaction of sensitive values in logs and error messages.

Two things go wrong with logging in a game that touches wallets:

1.  A secret reaches a log line. Private keys, API tokens and session
    credentials must never be written anywhere, at any level, ever.
2.  A *public but personal* identifier reaches a log line in full. A wallet
    address is public on-chain, but a log full of them is a ready-made map of
    who plays what, and logs travel further than databases do.

The answer to (1) is to never put secrets in log calls, enforced by a filter
that catches the mistake anyway. The answer to (2) is to log a stable, truncated
form -- enough to correlate two lines, not enough to enumerate players.

Install once at process start::

    from rivalforge.security.redaction import install_redaction
    install_redaction()
"""

from __future__ import annotations

import logging
import re
from typing import Final, Iterable, Pattern

__all__ = [
    "REDACTED",
    "RedactionFilter",
    "install_redaction",
    "redact",
    "short_address",
]

REDACTED: Final = "[redacted]"

#: Keys whose *value* is always a secret, in `key=value`, `key: value` and
#: JSON-ish `"key": "value"` shapes. Matching is case-insensitive.
_SECRET_KEYS: Final = (
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "bearer",
    "token",
    "authorization",
    "auth",
    "seed_phrase",
    "mnemonic",
    "keypair",
    "session_id",
    "cookie",
)


#: Authentication schemes that sit between the key and the value it protects.
#: Without these, `authorization: Bearer <token>` redacts the word "Bearer"
#: and leaves the token in the log -- which is the whole leak, intact.
_AUTH_SCHEMES: Final = ("bearer", "basic", "token", "digest", "apikey")


def _key_value_patterns(keys: Iterable[str]) -> list[Pattern[str]]:
    """Build the `key = value` patterns for every secret key name."""
    alternation = "|".join(re.escape(k) for k in keys)
    schemes = "|".join(_AUTH_SCHEMES)
    return [
        # key=value / key: value / "key": "value" / key: Bearer value.
        # The value runs to the first delimiter, optionally preceded by an
        # auth scheme word which is swallowed along with it.
        re.compile(
            rf'(?i)(["\']?\b(?:{alternation})\b["\']?\s*[:=]\s*)'
            rf'(["\']?)(?:(?:{schemes})\s+)?[^\s,;}}\)\]"\']+\2'
        ),
    ]


#: A Telegram bot token: a numeric bot id, a colon, then the secret half.
#: Whoever holds one *is* the bot -- they can read every message sent to it and
#: post as it. The token lives in a URL, which is exactly the kind of string
#: that ends up in an exception message when a request fails.
#: No leading word boundary: the token appears in a URL as `/bot<token>`,
#: where there is no boundary between the "t" and the first digit -- which
#: is precisely the string that ends up in a failed-request traceback.
_BOT_TOKEN: Final = re.compile(r"(?<!\d)(\d{6,12}):[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")


def _redact_value(match: "re.Match[str]") -> str:
    """Keep the key, drop the value."""
    return f"{match.group(1)}{REDACTED}"


def _truncate_address(match: "re.Match[str]") -> str:
    return short_address(match.group(1))


def _redact_dsn_credentials(match: "re.Match[str]") -> str:
    """Keep the scheme, host and database; drop the credentials."""
    return f"{match.group(1)}{REDACTED}@"


def _redact_bot_token(match: "re.Match[str]") -> str:
    """Keep the bot id, drop the secret half. The id is public in every @mention."""
    return f"{match.group(1)}:{REDACTED}"


def _replace_wholly(match: "re.Match[str]") -> str:
    return REDACTED


#: Pattern paired with what to put in its place.
#:
#: Each rule carries its own replacement rather than being dispatched on its
#: index in this tuple. The index form worked until a rule had to be inserted
#: in the middle, at which point two other rules quietly started using the
#: wrong replacement.
#:
#: Order matters: the bot token runs before the base58 rule, which would
#: otherwise truncate the token's secret half into something that still looks
#: redacted but is not.
_RULES: Final[tuple[tuple[Pattern[str], object], ...]] = (
    *((p, _redact_value) for p in _key_value_patterns(_SECRET_KEYS)),
    (_BOT_TOKEN, _redact_bot_token),
    # A bare Solana-shaped base58 blob. Truncated rather than removed so two
    # log lines about the same wallet can still be correlated.
    (re.compile(r"\b([1-9A-HJ-NP-Za-km-z]{32,44})\b"), _truncate_address),
    # PEM private key blocks, in case one is ever interpolated into a message.
    (
        re.compile(
            r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        _replace_wholly,
    ),
    # JWT-shaped triples.
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        _replace_wholly,
    ),
    # Connection strings with embedded credentials. A DSN in a stack trace is
    # a leaked database password, and a driver error is exactly the place one
    # shows up. The credentials go; the host and database stay, because those
    # are what make the line useful to whoever is reading it.
    (
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://)"
            r"[^\s:/@]+(?::[^\s@]*)?@",
        ),
        _redact_dsn_credentials,
    ),
)


def short_address(address: str, *, lead: int = 4, tail: int = 4) -> str:
    """Return a stable, truncated form of an address: ``7pNy...1u2r``.

    Deterministic, so the same wallet reads the same way across log lines,
    while the full value never lands in the log.
    """
    if len(address) <= lead + tail + 3:
        return address
    return f"{address[:lead]}...{address[-tail:]}"


def redact(text: str) -> str:
    """Redact secrets and truncate address-shaped blobs in a block of text."""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


class RedactionFilter(logging.Filter):
    """A logging filter that redacts the rendered message of every record.

    Attached to a *handler* rather than a logger, so it applies to records that
    propagate up from libraries as well as our own.

    This is a backstop, not a licence: code should still never pass a secret to
    a log call. The filter exists because "should never" is not "does never".
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - a broken %-format in a log call
            # Redact the raw template instead of dropping the record: losing a
            # log line to a formatting bug is worse than an unformatted one.
            record.msg = redact(str(record.msg))
            record.args = ()
            return True

        cleaned = redact(rendered)
        if cleaned != rendered:
            record.msg = cleaned
            record.args = ()

        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def install_redaction(logger: logging.Logger | None = None) -> None:
    """Attach `RedactionFilter` to every handler of `logger` (root by default).

    Idempotent: calling it twice does not stack filters.
    """
    target = logger if logger is not None else logging.getLogger()
    for handler in target.handlers:
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(RedactionFilter())
