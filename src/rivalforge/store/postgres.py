"""Postgres adapters for the storage ports.

Implements `PlayerStore`, `SessionStore` and `AuditSink` against Postgres, so a
multi-worker deployment shares state that the memory and file backends cannot.

## Security

**Every query is parameterised.** There is no string interpolation of a value
into SQL anywhere in this module, and a test asserts it by scanning the source
for f-strings and `%` formatting inside query literals. Table names are
compile-time constants, never inputs.

**The connection string is a secret.** Read from the environment only, never a
CLI argument (visible in `ps`), never a file in the repository. The redaction
filter scrubs the credentials out of any DSN that reaches a log -- keeping the
scheme, host and database, which are what make the line diagnosable -- and a
test covers it. A driver error is exactly where a connection string shows up.

**TLS is required by default.** `sslmode=require` is appended when the URL does
not set one. A managed database reached over the public internet without TLS
hands every query to anyone on the path.

**Least data.** The schema stores no IP address, user agent, device
fingerprint, geolocation, email or real name. The comment in `schema.sql`
records that as a decision rather than an omission.

## Availability

A database is a dependency like any other, so it goes through the same
resilience layer as the RPC provider: bounded retries on transient errors, a
circuit breaker, and a connection timeout. A game that hangs because Postgres
is slow is a game that is down.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Final, Sequence
from urllib.parse import urlparse, urlunparse

from ..auth.audit import AuditRecord
from ..auth.session import Session
from ..auth.session_store import SESSION_STORES
from ..plugins.ports import PlayerRecord
from ..plugins.registries import PLAYER_STORES
from .records import (
    MAX_POINTS_DELTA,
    clean_player_record,
    load_player_record,
    validate_player_id,
)
from ..security.validation import ValidationError, validate_int
from ..plugins.resilience import (
    CircuitBreaker,
    PermanentError,
    RetryPolicy,
    TransientError,
    call_with_retries,
)

logger = logging.getLogger(__name__)

__all__ = [
    "PostgresPlayerStore",
    "PostgresSessionStore",
    "PostgresAuditSink",
    "connection_url",
    "apply_schema",
    "PostgresUnavailable",
]

#: How long to wait for a connection before giving up. A player is waiting on
#: this inside a chat message.
DEFAULT_CONNECT_TIMEOUT: Final = 5

SCHEMA_VERSION: Final = 1


class PostgresUnavailable(RuntimeError):
    """The database could not be reached or configured."""


def connection_url(env: dict[str, str] | None = None) -> str:
    """The connection URL, from the environment, with TLS enforced.

    Railway supplies `DATABASE_URL`. `RIVALFORGE_DATABASE_URL` takes precedence
    so the game can be pointed at its own database in an environment that
    already uses `DATABASE_URL` for something else.

    Raises:
        PostgresUnavailable: if nothing is configured. Failing loudly beats
            silently falling back to an in-memory store that looks like it
            persists and does not.
    """
    environment = os.environ if env is None else env
    url = (
        environment.get("RIVALFORGE_DATABASE_URL")
        or environment.get("DATABASE_URL")
        or ""
    ).strip()
    if not url:
        raise PostgresUnavailable(
            "no database configured; set RIVALFORGE_DATABASE_URL or DATABASE_URL"
        )
    return _require_tls(url, environment)


def _require_tls(url: str, env: dict[str, str]) -> str:
    """Append `sslmode=require` unless one is set, or unless it is local.

    A managed database reached across the internet without TLS hands every
    query, and the password, to anyone on the path. Localhost is exempt because
    a loopback connection has no path to intercept, and demanding TLS there
    only stops people running the tests.
    """
    if "sslmode=" in url:
        return url
    host = (urlparse(url).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1", ""):
        return url
    if env.get("RIVALFORGE_DB_ALLOW_INSECURE", "").lower() in ("1", "true", "yes"):
        logger.warning("TLS to the database is disabled by configuration")
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}sslmode=require"


def _redact_url(url: str) -> str:
    """A form of the URL safe to log: host and database only, no credentials."""
    try:
        parsed = urlparse(url)
        return urlunparse(
            (parsed.scheme, parsed.hostname or "", parsed.path, "", "", "")
        )
    except Exception:  # pragma: no cover - defensive
        return "<unparseable url>"


def _connect(url: str, *, timeout: int = DEFAULT_CONNECT_TIMEOUT):
    """Open one connection, mapping driver failures onto our typed errors."""
    try:
        import psycopg  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - guarded at start-up
        raise PostgresUnavailable(
            "psycopg is not installed; pip install 'rivalforge[postgres]'"
        ) from exc

    try:
        return psycopg.connect(url, connect_timeout=timeout, autocommit=True)
    except psycopg.OperationalError as exc:
        # Could be a bad password (permanent) or a down host (transient). We
        # cannot reliably tell them apart from the driver, and treating it as
        # transient is the safer default: a retry costs milliseconds, whereas
        # marking a recoverable outage permanent takes the game down until a
        # human notices.
        raise TransientError(f"cannot connect to the database: {exc}") from exc
    except Exception as exc:
        raise PermanentError(f"database connection rejected: {exc}") from exc


class _PostgresBacked:
    """Shared connection handling for the three adapters.

    One connection per adapter, reopened on failure. Not a pool: a pool is the
    right answer under real concurrency and the wrong thing to hand-roll here,
    so this is deliberately the simple version until a load test says otherwise.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        policy: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
    ) -> None:
        self._url = url or connection_url()
        self._policy = policy or RetryPolicy(attempts=3, base_delay=0.1, total_timeout=8.0)
        self._breaker = breaker or CircuitBreaker("postgres", threshold=5, cooldown=15.0)
        self._connect_timeout = connect_timeout
        self._conn = None

    @property
    def dsn_for_logging(self) -> str:
        return _redact_url(self._url)

    def _connection(self):
        if self._conn is None or self._conn.closed:
            self._conn = _connect(self._url, timeout=self._connect_timeout)
        return self._conn

    def _run(self, sql: str, params: tuple = (), *, fetch: str = "none"):
        """Execute one parameterised statement with retries and a breaker.

        `sql` is always a module-level constant. `params` carries every value.
        """
        def attempt():
            try:
                with self._connection().cursor() as cursor:
                    cursor.execute(sql, params)
                    if fetch == "one":
                        return cursor.fetchone()
                    if fetch == "all":
                        return cursor.fetchall()
                    return cursor.rowcount
            except Exception as exc:
                # Drop the connection so the next attempt reconnects rather
                # than reusing one that may be in a failed transaction.
                try:
                    if self._conn is not None:
                        self._conn.close()
                finally:
                    self._conn = None
                raise TransientError(f"query failed: {type(exc).__name__}") from exc

        return call_with_retries(
            attempt, policy=self._policy, breaker=self._breaker, description="postgres query"
        )

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None


def apply_schema(url: str | None = None) -> int:
    """Create the schema if it is not there. Idempotent.

    Returns the schema version now in place.
    """
    target = url or connection_url()
    sql = (
        resources.files("rivalforge.store").joinpath("schema.sql").read_text(encoding="utf-8")
    )
    connection = _connect(target)
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql)
            cursor.execute(
                "INSERT INTO schema_version (version) VALUES (%s) "
                "ON CONFLICT (version) DO NOTHING",
                (SCHEMA_VERSION,),
            )
        logger.info("schema applied to %s", _redact_url(target))
        return SCHEMA_VERSION
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Players
# ---------------------------------------------------------------------------

_UPSERT_PLAYER = """
INSERT INTO players (player_id, wallet, display_name, points, wins, losses, created_at)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (player_id) DO UPDATE SET
    wallet = EXCLUDED.wallet,
    display_name = EXCLUDED.display_name,
    points = EXCLUDED.points,
    wins = EXCLUDED.wins,
    losses = EXCLUDED.losses,
    updated_at = now()
"""

_GET_PLAYER = """
SELECT player_id, wallet, display_name, points, wins, losses, created_at
FROM players WHERE player_id = %s
"""

_RECORD_RESULT = """
UPDATE players SET
    points = GREATEST(0, points + %s),
    wins   = wins   + %s,
    losses = losses + %s,
    updated_at = now()
WHERE player_id = %s
RETURNING player_id, wallet, display_name, points, wins, losses, created_at
"""

_LEADERBOARD = """
SELECT player_id, wallet, display_name, points, wins, losses, created_at
FROM players ORDER BY points DESC, display_name ASC LIMIT %s
"""


@PLAYER_STORES.register("postgres")
class PostgresPlayerStore(_PostgresBacked):
    """Players and the ladder, in Postgres."""

    name = "postgres"

    @staticmethod
    def _row_to_record(row) -> PlayerRecord:
        """Validate on the way out, not only on the way in.

        A migration, a hand-run UPDATE or another writer can all leave a row
        that breaks the application's rules. Loading it blindly produces
        behaviour no test predicts.
        """
        return load_player_record(*row)

    def get_player(self, player_id: str) -> PlayerRecord | None:
        row = self._run(_GET_PLAYER, (validate_player_id(player_id),), fetch="one")
        return self._row_to_record(row) if row else None

    def upsert_player(self, record: PlayerRecord) -> PlayerRecord:
        clean = clean_player_record(record)
        self._run(
            _UPSERT_PLAYER,
            (
                clean.player_id, clean.wallet, clean.display_name,
                clean.points, clean.wins, clean.losses, clean.created_at,
            ),
        )
        stored = self.get_player(clean.player_id)
        if stored is None:  # pragma: no cover - only if a concurrent delete raced
            raise TransientError("player vanished immediately after upsert")
        return stored

    def record_result(self, player_id: str, *, won: bool, points_delta: int) -> PlayerRecord:
        """Apply a result atomically.

        The arithmetic happens in SQL rather than read-modify-write in Python,
        so two workers finishing two matches for one player cannot lose an
        update to a race. `GREATEST(0, ...)` keeps points non-negative in the
        same statement, matching the memory store and the CHECK constraint.
        """
        checked_id = validate_player_id(player_id)
        # A single match moves the ladder by 15 at most. Bounding it here stops
        # a buggy or compromised caller minting an unreachable score, and the
        # bound is enforced identically in the memory store.
        delta = validate_int(
            points_delta, field="points_delta",
            minimum=-MAX_POINTS_DELTA, maximum=MAX_POINTS_DELTA,
        )
        if not isinstance(won, bool):
            raise ValidationError("won", f"expected a boolean, got {type(won).__name__}")

        row = self._run(
            _RECORD_RESULT,
            (delta, 1 if won else 0, 0 if won else 1, checked_id),
            fetch="one",
        )
        if row is None:
            raise KeyError(f"unknown player {checked_id!r}")
        return self._row_to_record(row)

    def leaderboard(self, *, limit: int = 50) -> Sequence[PlayerRecord]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit", f"expected an integer, got {type(limit).__name__}")
        bounded = max(1, min(limit, 500))
        rows = self._run(_LEADERBOARD, (bounded,), fetch="all") or ()
        return tuple(self._row_to_record(row) for row in rows)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

_PUT_SESSION = """
INSERT INTO sessions (token_hash, wallet, created_at, expires_at)
VALUES (%s, %s, %s, %s)
ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
"""
_GET_SESSION = "SELECT token_hash, wallet, created_at, expires_at FROM sessions WHERE token_hash = %s"
_DELETE_SESSION = "DELETE FROM sessions WHERE token_hash = %s"
_DELETE_WALLET_SESSIONS = "DELETE FROM sessions WHERE wallet = %s"
_PURGE_SESSIONS = "DELETE FROM sessions WHERE expires_at <= %s"
_COUNT_SESSIONS = "SELECT count(*) FROM sessions"
_OLDEST_SESSION = "SELECT token_hash FROM sessions ORDER BY expires_at ASC LIMIT 1"


@SESSION_STORES.register("postgres")
class PostgresSessionStore(_PostgresBacked):
    """Sessions shared across workers.

    Stores the token *hash* only, exactly as the memory and file stores do. The
    security policy lives in `SessionService`; this holds bytes.
    """

    name = "postgres"

    def put(self, session) -> None:
        self._run(
            _PUT_SESSION,
            (session.token_hash, session.wallet, session.created_at, session.expires_at),
        )

    def get(self, token_hash: str):
        row = self._run(_GET_SESSION, (token_hash,), fetch="one")
        if row is None:
            return None
        return Session(
            token_hash=row[0], wallet=row[1], created_at=row[2], expires_at=row[3]
        )

    def delete(self, token_hash: str) -> bool:
        return bool(self._run(_DELETE_SESSION, (token_hash,)))

    def delete_wallet(self, wallet: str) -> int:
        return int(self._run(_DELETE_WALLET_SESSIONS, (wallet,)) or 0)

    def purge_expired(self, now: datetime) -> int:
        return int(self._run(_PURGE_SESSIONS, (now,)) or 0)

    def oldest_token_hash(self) -> str | None:
        row = self._run(_OLDEST_SESSION, fetch="one")
        return row[0] if row else None

    def __len__(self) -> int:
        row = self._run(_COUNT_SESSIONS, fetch="one")
        return int(row[0]) if row else 0


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

_WRITE_AUDIT = """
INSERT INTO audit_events (at, event, wallet, outcome, reason)
VALUES (%s, %s, %s, %s, %s)
"""
_READ_AUDIT = """
SELECT at, event, wallet, outcome, reason
FROM audit_events ORDER BY at DESC, id DESC LIMIT %s
"""
_READ_AUDIT_FOR_WALLET = """
SELECT at, event, wallet, outcome, reason
FROM audit_events WHERE wallet = %s ORDER BY at DESC, id DESC LIMIT %s
"""


class PostgresAuditSink(_PostgresBacked):
    """A durable audit trail.

    Append-only by use: this class offers no update or delete. Enforcing that
    at the database level needs a role without UPDATE/DELETE on the table,
    which is a deployment concern and is written up in docs/SECURITY.md rather
    than pretended at here.
    """

    name = "postgres"
    durable = True

    def write(self, record: AuditRecord) -> None:
        self._run(
            _WRITE_AUDIT,
            (record.at, record.event.value, record.wallet, record.outcome, record.reason),
        )

    def records(self, *, limit: int = 100) -> tuple[AuditRecord, ...]:
        from ..auth.audit import AuditEvent  # noqa: PLC0415

        rows = self._run(_READ_AUDIT, (max(1, min(int(limit), 1000)),), fetch="all") or ()
        return tuple(
            AuditRecord(
                at=row[0], event=AuditEvent(row[1]), wallet=row[2],
                outcome=row[3], reason=row[4],
            )
            for row in rows
        )

    def for_wallet(self, wallet: str, *, limit: int = 100) -> tuple[AuditRecord, ...]:
        from ..auth.audit import AuditEvent  # noqa: PLC0415

        rows = self._run(
            _READ_AUDIT_FOR_WALLET, (wallet, max(1, min(int(limit), 1000))), fetch="all"
        ) or ()
        return tuple(
            AuditRecord(
                at=row[0], event=AuditEvent(row[1]), wallet=row[2],
                outcome=row[3], reason=row[4],
            )
            for row in rows
        )

    def __len__(self) -> int:
        row = self._run("SELECT count(*) FROM audit_events", fetch="one")
        return int(row[0]) if row else 0
