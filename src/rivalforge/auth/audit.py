"""Append-only audit trail.

Two rules, pulling against each other, and the whole design is where they meet:

1.  **Record enough to investigate abuse.** If someone farms a ladder or
    attacks the auth endpoint, an operator has to be able to reconstruct what
    happened, in order, afterwards.
2.  **Record nothing else.** Every field stored is a field that must be
    protected, can be subpoenaed, and can leak. The cheapest way to keep data
    safe is not to have it.

## What is recorded

Wallet address, event kind, outcome, a UTC timestamp, and a short reason. The
wallet is the identity being authenticated, so an audit trail without it
records nothing useful.

## What is deliberately *not* recorded

IP addresses. User agents. Device or browser fingerprints. Geolocation. Email
addresses. Session tokens or their hashes. Signatures. Challenge text. None of
these are needed to answer "did this wallet authenticate, when, and did it
work", and each one is a liability with no matching benefit.

## Audit records are not application logs

They are different things with different rules:

* the **audit trail** holds full wallet addresses, because that is its job, and
  it should live behind the same access controls as the database;
* the **application log** never does -- the redaction filter truncates every
  address that reaches it, because logs travel further than databases do.

Confusing the two is how a full wallet list ends up in a log aggregator that
half the company can search.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final, Iterable, Protocol, runtime_checkable

from ..security.redaction import short_address

logger = logging.getLogger(__name__)

__all__ = [
    "AuditEvent",
    "AuditRecord",
    "AuditSink",
    "InMemoryAuditSink",
    "AuditTrail",
    "MAX_AUDIT_RECORDS",
]

#: Ring-buffer bound for the in-memory sink. A durable sink has no such limit.
MAX_AUDIT_RECORDS: Final = 100_000

#: Reasons are ours, not user input, but bound them anyway -- an unbounded
#: string reaching storage is how a log becomes a denial-of-service target.
_MAX_REASON: Final = 120


class AuditEvent(str, Enum):
    """Everything worth recording. A closed set, so the trail stays queryable."""

    CHALLENGE_ISSUED = "challenge_issued"
    CHALLENGE_RATE_LIMITED = "challenge_rate_limited"
    AUTH_SUCCEEDED = "auth_succeeded"
    AUTH_FAILED = "auth_failed"
    SESSION_REVOKED = "session_revoked"
    OWNERSHIP_VERIFIED = "ownership_verified"
    OWNERSHIP_REJECTED = "ownership_rejected"
    OWNERSHIP_UNAVAILABLE = "ownership_unavailable"
    MATCH_RECORDED = "match_recorded"


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One immutable entry."""

    at: datetime
    event: AuditEvent
    wallet: str | None
    outcome: str
    reason: str = ""

    def redacted(self) -> str:
        """A one-line form safe for an application log."""
        who = short_address(self.wallet) if self.wallet else "-"
        tail = f" ({self.reason})" if self.reason else ""
        return f"{self.at.isoformat()} {self.event.value} {who} {self.outcome}{tail}"


@runtime_checkable
class AuditSink(Protocol):
    """Somewhere audit records go. Memory now, a table later."""

    name: str

    def write(self, record: AuditRecord) -> None:
        ...


class InMemoryAuditSink:
    """A bounded ring buffer.

    Adequate for development and for a single process. It is explicitly *not*
    durable, and `AuditTrail` says so at start-up rather than letting an
    operator assume otherwise.
    """

    name = "memory"
    durable = False

    __slots__ = ("_records", "_lock")

    def __init__(self, max_records: int = MAX_AUDIT_RECORDS) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self._records: deque[AuditRecord] = deque(maxlen=max_records)
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    def records(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def for_wallet(self, wallet: str) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(r for r in self._records if r.wallet == wallet)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


class AuditTrail:
    """The façade every caller uses.

    Writing to the trail must never break the thing being audited. A sink that
    raises is logged and swallowed -- losing an audit record is bad, but
    failing a player's login because the audit backend is down is worse, and
    the alternative is an availability hole an attacker can trigger on purpose.
    """

    __slots__ = ("_sink", "_clock")

    def __init__(self, sink: AuditSink, clock) -> None:
        self._sink = sink
        self._clock = clock
        if not getattr(sink, "durable", False):
            logger.info(
                "audit sink %r is not durable; records are lost on restart",
                getattr(sink, "name", type(sink).__name__),
            )

    def record(
        self,
        event: AuditEvent,
        *,
        wallet: str | None = None,
        outcome: str,
        reason: str = "",
    ) -> AuditRecord:
        now = self._clock.now()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        entry = AuditRecord(
            at=now,
            event=event,
            wallet=wallet,
            outcome=outcome[:32],
            reason=reason[:_MAX_REASON],
        )
        try:
            self._sink.write(entry)
        except Exception:
            logger.warning("audit sink write failed", exc_info=True)
        return entry

    # Convenience wrappers, so call sites read as intent rather than plumbing.

    def challenge_issued(self, wallet: str) -> None:
        self.record(AuditEvent.CHALLENGE_ISSUED, wallet=wallet, outcome="ok")

    def challenge_rate_limited(self, wallet: str) -> None:
        self.record(AuditEvent.CHALLENGE_RATE_LIMITED, wallet=wallet, outcome="rejected")

    def auth_succeeded(self, wallet: str) -> None:
        self.record(AuditEvent.AUTH_SUCCEEDED, wallet=wallet, outcome="ok")

    def auth_failed(self, wallet: str | None, reason: str) -> None:
        # The specific reason is safe *here* -- an audit trail is for an
        # operator. It is never returned to the caller, where it would be an
        # enumeration oracle.
        self.record(AuditEvent.AUTH_FAILED, wallet=wallet, outcome="rejected", reason=reason)

    def ownership(self, wallet: str, mint: str, result) -> None:
        if result.verified:
            event, outcome = AuditEvent.OWNERSHIP_VERIFIED, "ok"
        elif result.checked:
            event, outcome = AuditEvent.OWNERSHIP_REJECTED, "rejected"
        else:
            event, outcome = AuditEvent.OWNERSHIP_UNAVAILABLE, "unavailable"
        # The mint is truncated: which NFT someone plays is not needed to
        # investigate abuse, and the wallet already identifies the actor.
        self.record(event, wallet=wallet, outcome=outcome, reason=short_address(mint))
