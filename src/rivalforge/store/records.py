"""Validation at the storage boundary, in both directions.

Never trust, always validate -- and a database is a boundary like any other.

Validating on the way **in** is obvious: a caller can hand a store an unbounded
display name, a malformed wallet, or a points delta of ten million, and a store
that writes it has just made the problem permanent.

Validating on the way **out** is the half that usually gets skipped, on the
reasoning that "we wrote it, so it must be fine". That reasoning fails in four
ordinary ways:

* a migration backfilled a column wrongly;
* an operator ran an UPDATE by hand;
* a different service writes the same table;
* the row predates a constraint that was added later.

In every case the game loads a record that violates its own rules and behaves
in ways no test predicts. A row that fails validation is a loud error, not a
silently loaded object.

The two directions are deliberately asymmetric:

* **Writes reject.** The caller is here, can be told, and can fix it.
* **Reads reject too**, but with a distinct error type, because the fault is in
  the data rather than in the call, and an operator needs to know which.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Final

from ..plugins.ports import PlayerRecord
from ..security.validation import (
    ValidationError,
    sanitize_display_name,
    validate_int,
    validate_mint_address,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CorruptRecord",
    "MAX_PLAYER_ID",
    "MAX_POINTS",
    "MAX_POINTS_DELTA",
    "validate_player_id",
    "validate_wallet_or_none",
    "clean_player_record",
    "load_player_record",
]

#: A player id is ours to mint, so it can be strict. Long enough for a UUID or
#: a `telegram:123456789`, short enough that it cannot be used as storage.
MAX_PLAYER_ID: Final = 64
_PLAYER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_:.\-]{0,63}$")

#: Ladder bounds. High enough that no honest player reaches them, low enough
#: that a bug or an attack cannot mint an unreachable score.
MAX_POINTS: Final = 10_000_000
MAX_TALLY: Final = 10_000_000

#: A single match can move the ladder by at most this much. The engine's real
#: numbers are 15 and -5; this is the outer bound that stops a compromised or
#: buggy caller awarding a million points in one call.
MAX_POINTS_DELTA: Final = 1_000


class CorruptRecord(RuntimeError):
    """A stored row does not satisfy the rules the application relies on.

    Distinct from `ValidationError`, which means the *caller* passed something
    bad. This means the *data* is bad, which is an operational problem and
    wants a different response: investigate the row, do not retry the call.
    """


def validate_player_id(value: object, *, field: str = "player_id") -> str:
    """Validate an internal player identifier."""
    if not isinstance(value, str):
        raise ValidationError(field, f"expected a string, got {type(value).__name__}")
    if not _PLAYER_ID.match(value):
        raise ValidationError(
            field,
            f"must be 1-{MAX_PLAYER_ID} characters of letters, digits, _ : . or -, "
            "starting with a letter or digit",
        )
    return value


def validate_wallet_or_none(value: object, *, field: str = "wallet") -> str | None:
    """Validate a wallet address, allowing None.

    None is a first-class value here: a player must be able to exist, fight and
    appear on a ladder before ever connecting a wallet.
    """
    if value is None:
        return None
    return validate_mint_address(value, field=field)


def clean_player_record(record: PlayerRecord) -> PlayerRecord:
    """Validate and normalise a record on its way into storage.

    Returns a new record with the display name sanitized. Raises rather than
    coercing anything else: silently clamping a caller's 5,000,000 points to
    the maximum would hide the bug that produced it.
    """
    if not isinstance(record, PlayerRecord):
        raise ValidationError("record", f"expected a PlayerRecord, got {type(record).__name__}")

    created_at = record.created_at
    if not isinstance(created_at, datetime):
        raise ValidationError("created_at", "must be a datetime")
    if created_at.tzinfo is None:
        # A naive timestamp compares wrongly against every aware one, so fix it
        # at the boundary rather than letting it into the database.
        created_at = created_at.replace(tzinfo=timezone.utc)

    return PlayerRecord(
        player_id=validate_player_id(record.player_id),
        wallet=validate_wallet_or_none(record.wallet),
        # Sanitized, not rejected: the acceptable set of names is fuzzy, and
        # this strips the zero-width and bidi characters used for spoofing.
        display_name=sanitize_display_name(record.display_name),
        points=validate_int(record.points, field="points", minimum=0, maximum=MAX_POINTS),
        wins=validate_int(record.wins, field="wins", minimum=0, maximum=MAX_TALLY),
        losses=validate_int(record.losses, field="losses", minimum=0, maximum=MAX_TALLY),
        created_at=created_at,
        metadata=record.metadata,
    )


def load_player_record(
    player_id: object,
    wallet: object,
    display_name: object,
    points: object,
    wins: object,
    losses: object,
    created_at: object,
) -> PlayerRecord:
    """Build a record from stored columns, validating as it goes.

    Raises:
        CorruptRecord: if the row violates the application's rules. The row is
            identified in the message so an operator can go and look at it, but
            the offending *values* are not echoed -- a corrupt row can contain
            anything, including something hostile that was written by another
            path, and copying it into an exception message is how that reaches
            a log or a screen.
    """
    try:
        return PlayerRecord(
            player_id=validate_player_id(player_id),
            wallet=validate_wallet_or_none(wallet),
            display_name=sanitize_display_name(display_name),
            points=validate_int(points, field="points", minimum=0, maximum=MAX_POINTS),
            wins=validate_int(wins, field="wins", minimum=0, maximum=MAX_TALLY),
            losses=validate_int(losses, field="losses", minimum=0, maximum=MAX_TALLY),
            created_at=(
                created_at
                if isinstance(created_at, datetime)
                else _reject("created_at is not a timestamp")
            ),
        )
    except ValidationError as exc:
        identifier = player_id if isinstance(player_id, str) else "<unreadable id>"
        logger.error("corrupt player row %r: %s", identifier[:MAX_PLAYER_ID], exc.field)
        raise CorruptRecord(
            f"stored player row {identifier[:MAX_PLAYER_ID]!r} failed validation "
            f"on {exc.field}"
        ) from exc


def _reject(reason: str):
    raise ValidationError("row", reason)
