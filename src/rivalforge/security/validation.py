"""Input validation primitives.

Every value that crosses a trust boundary passes through this module. A trust
boundary is any point where data originates outside the engine: a wallet
address typed by a player, a display name, a content file on disk, a number
arriving from a network handler.

Design rules, learned the hard way from the previous codebase:

1.  **Validators raise, they never coerce silently.** A validator that returns
    a safe default on bad input is how a broken game ships: the caller cannot
    tell "valid zero" from "invalid, defaulted to zero". Every function here
    raises `ValidationError` and the caller decides.
2.  **Bounds are mandatory, not optional.** Anything with a numeric range takes
    an explicit range. Anything with a length takes an explicit maximum.
3.  **Reject, do not sanitize, structural input.** Names are sanitized because
    the set of acceptable names is fuzzy. Addresses, identifiers and enum
    values are *rejected* when malformed, because the acceptable set is exact.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final, Iterable, TypeVar

__all__ = [
    "ValidationError",
    "MAX_DISPLAY_NAME_LENGTH",
    "validate_mint_address",
    "sanitize_display_name",
    "validate_int",
    "validate_float",
    "validate_identifier",
    "validate_choice",
    "validate_text_field",
    "b58decode",
    "b58encode",
]


class ValidationError(ValueError):
    """Raised when untrusted input fails validation.

    Carries a `field` so a caller can build a message for the player without
    string-matching on the reason.
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"{field}: {reason}")


# --------------------------------------------------------------------------
# Base58 (Bitcoin/Solana alphabet)
# --------------------------------------------------------------------------

_B58_ALPHABET: Final = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX: Final = {c: i for i, c in enumerate(_B58_ALPHABET)}

#: A Solana public key is 32 bytes, which is 32-44 base58 characters.
_MINT_MIN_CHARS: Final = 32
_MINT_MAX_CHARS: Final = 44
_MINT_BYTES: Final = 32


def b58decode(value: str) -> bytes:
    """Decode base58 without a third-party dependency.

    Raises:
        ValidationError: if `value` contains a character outside the alphabet.
    """
    if not value:
        raise ValidationError("base58", "empty string")

    num = 0
    for char in value:
        digit = _B58_INDEX.get(char)
        if digit is None:
            raise ValidationError("base58", "contains a non-base58 character")
        num = num * 58 + digit

    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""

    # Leading '1's are leading zero bytes and are lost in the integer form.
    leading_zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeros + body


def b58encode(data: bytes) -> str:
    """Encode bytes as base58. The inverse of `b58decode`.

    Not needed to *validate* an address, but needed to construct one -- by
    tests that generate valid mints, and by the wallet layer that will encode
    keys for display. One shared, round-trip-tested implementation is safer
    than a second hand-rolled one in a test helper.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValidationError("base58", f"expected bytes, got {type(data).__name__}")
    if not data:
        return ""

    num = int.from_bytes(data, "big")
    out: list[str] = []
    while num > 0:
        num, remainder = divmod(num, 58)
        out.append(_B58_ALPHABET[remainder])

    # Leading zero bytes are '1's, and are invisible in the integer form.
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeros + "".join(reversed(out))


def validate_mint_address(value: object, *, field: str = "mint_address") -> str:
    """Validate a Solana mint address and return it unchanged.

    The address is the single most security-relevant identifier in the game: it
    decides which fighter a player gets and, later, which NFT is checked
    on-chain. It is validated structurally here and verified for *ownership*
    elsewhere -- this function makes no ownership claim.
    """
    if not isinstance(value, str):
        raise ValidationError(field, f"expected a string, got {type(value).__name__}")
    if not (_MINT_MIN_CHARS <= len(value) <= _MINT_MAX_CHARS):
        raise ValidationError(
            field,
            f"expected {_MINT_MIN_CHARS}-{_MINT_MAX_CHARS} characters, got {len(value)}",
        )

    decoded = b58decode(value)  # raises on a bad alphabet
    if len(decoded) != _MINT_BYTES:
        raise ValidationError(field, f"decodes to {len(decoded)} bytes, expected {_MINT_BYTES}")
    return value


# --------------------------------------------------------------------------
# Free text
# --------------------------------------------------------------------------

MAX_DISPLAY_NAME_LENGTH: Final = 24

#: Unicode general categories that have no business in a display name:
#: Cc control, Cf format (includes zero-width joiners and bidi overrides),
#: Cs surrogate, Co private use, Cn unassigned.
_FORBIDDEN_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

_WHITESPACE_RUN = re.compile(r"\s+")


def sanitize_display_name(value: object, *, field: str = "display_name") -> str:
    """Normalise and sanitize a player-supplied display name.

    Applied, in order:

    * NFKC normalisation, so visually identical names compare equal and
      compatibility characters cannot be used to smuggle look-alikes;
    * removal of every control, format, surrogate, private-use and unassigned
      code point -- this is what stops zero-width joiners and right-to-left
      overrides being used to spoof another player's name;
    * whitespace-run collapsing and trimming;
    * a hard length cap.

    Raises:
        ValidationError: if nothing printable survives, or the input is not a
            string. An empty result is an error rather than a silent default,
            so a caller can prompt the player again.
    """
    if not isinstance(value, str):
        raise ValidationError(field, f"expected a string, got {type(value).__name__}")

    normalised = unicodedata.normalize("NFKC", value)
    kept = "".join(c for c in normalised if unicodedata.category(c) not in _FORBIDDEN_CATEGORIES)
    collapsed = _WHITESPACE_RUN.sub(" ", kept).strip()

    if not collapsed:
        raise ValidationError(field, "contains no printable characters")
    return collapsed[:MAX_DISPLAY_NAME_LENGTH]


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def validate_identifier(value: object, *, field: str = "identifier") -> str:
    """Validate a machine identifier: lowercase snake_case, 1-64 characters.

    Used for content keys (battlefield ids, element names, ability ids). Keeping
    these to one strict shape is what makes the content loader able to detect a
    renamed key instead of silently reading `None`.
    """
    if not isinstance(value, str):
        raise ValidationError(field, f"expected a string, got {type(value).__name__}")
    if not _IDENTIFIER.match(value):
        raise ValidationError(
            field, "must be lowercase snake_case, start with a letter, max 64 characters"
        )
    return value


def validate_text_field(
    value: object, *, field: str, max_length: int, allow_empty: bool = False
) -> str:
    """Validate a bounded block of display text from a content file.

    Unlike `sanitize_display_name` this rejects rather than strips, because
    content files are authored by us: a control character in one is a bug in the
    content, not a hostile player, and should fail the build.
    """
    if not isinstance(value, str):
        raise ValidationError(field, f"expected a string, got {type(value).__name__}")
    if not allow_empty and not value.strip():
        raise ValidationError(field, "must not be empty")
    if len(value) > max_length:
        raise ValidationError(field, f"longer than {max_length} characters")
    for char in value:
        if unicodedata.category(char) in _FORBIDDEN_CATEGORIES:
            raise ValidationError(field, "contains a control or format character")
    return value


# --------------------------------------------------------------------------
# Numbers
# --------------------------------------------------------------------------


def validate_int(
    value: object, *, field: str, minimum: int, maximum: int
) -> int:
    """Validate a bounded integer.

    `bool` is rejected explicitly: it is a subclass of `int` in Python, and
    letting `True` through as `1` has been the root of real scoring bugs.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(field, f"expected an integer, got {type(value).__name__}")
    if not (minimum <= value <= maximum):
        raise ValidationError(field, f"must be between {minimum} and {maximum}, got {value}")
    return value


def validate_float(
    value: object, *, field: str, minimum: float, maximum: float
) -> float:
    """Validate a bounded, finite real number.

    NaN and the infinities are rejected: NaN silently poisons every comparison
    it touches, and either one entering a damage formula ends a match in a way
    no test would predict.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(field, f"expected a number, got {type(value).__name__}")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise ValidationError(field, "must be a finite number")
    if not (minimum <= number <= maximum):
        raise ValidationError(field, f"must be between {minimum} and {maximum}, got {number}")
    return number


T = TypeVar("T")


def validate_choice(value: object, *, field: str, allowed: Iterable[T]) -> T:
    """Validate that `value` is one of `allowed`, and return the allowed member.

    Returning the member rather than the input matters for enums: the caller
    gets the typed value, not a string that merely looks like one.
    """
    options = list(allowed)
    for option in options:
        if value == option:
            return option
    shown = ", ".join(sorted(str(o) for o in options))
    raise ValidationError(field, f"must be one of [{shown}], got {value!r}")
