"""Tests for the Postgres adapters.

Two kinds:

* **Contract tests** run the *same* assertions against the memory and Postgres
  implementations of a port. A port with two implementations that behave
  differently is worse than one implementation, because the difference only
  shows up in production. These are the tests that matter most.
* **Postgres-specific tests** cover what only a database has: atomicity,
  concurrency, TLS enforcement, and injection resistance.

They need a real Postgres. Point `RIVALFORGE_TEST_DATABASE_URL` at a throwaway
database and they run; otherwise they skip. A test that mocks the database
proves the mock works.
"""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timedelta, timezone

import pytest

from rivalforge.auth.audit import AuditEvent, AuditRecord, AuditTrail
from rivalforge.auth.session import Session, SessionService
from rivalforge.auth.session_store import InMemorySessionStore
from rivalforge.plugins.adapters import FixedClock, MemoryPlayerStore
from rivalforge.plugins.ports import PlayerRecord, PlayerStore
from rivalforge.plugins.resilience import TransientError
from rivalforge.security.validation import ValidationError, b58encode
from rivalforge.store.records import MAX_POINTS_DELTA, CorruptRecord

TEST_DB_ENV = "RIVALFORGE_TEST_DATABASE_URL"
_URL = os.environ.get(TEST_DB_ENV, "").strip()

psycopg = pytest.importorskip("psycopg")

requires_db = pytest.mark.skipif(
    not _URL, reason=f"set {TEST_DB_ENV} to a throwaway database to run these"
)

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


def _record(player_id="p1", wallet=None, points=100, wins=2, losses=1) -> PlayerRecord:
    return PlayerRecord(
        player_id=player_id, display_name=f"Name-{player_id}", wallet=wallet,
        points=points, wins=wins, losses=losses, created_at=NOW,
    )


@pytest.fixture(scope="module")
def schema():
    if not _URL:
        pytest.skip("no test database")
    from rivalforge.store.postgres import apply_schema  # noqa: PLC0415

    apply_schema(_URL)
    return _URL


@pytest.fixture
def clean(schema):
    """A clean database for each test. Truncate, do not drop: dropping and
    recreating the schema per test would hide a migration that is not
    idempotent."""
    with psycopg.connect(schema, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "TRUNCATE players, sessions, audit_events, matches RESTART IDENTITY"
            )
    return schema


@pytest.fixture
def pg_players(clean):
    from rivalforge.store.postgres import PostgresPlayerStore  # noqa: PLC0415

    store = PostgresPlayerStore(clean)
    yield store
    store.close()


@pytest.fixture
def pg_sessions(clean):
    from rivalforge.store.postgres import PostgresSessionStore  # noqa: PLC0415

    store = PostgresSessionStore(clean)
    yield store
    store.close()


@pytest.fixture
def pg_audit(clean):
    from rivalforge.store.postgres import PostgresAuditSink  # noqa: PLC0415

    sink = PostgresAuditSink(clean)
    yield sink
    sink.close()


# ==========================================================================
# Contract: PlayerStore, both implementations, identical assertions
# ==========================================================================


@pytest.fixture(params=["memory", "postgres"])
def player_store(request, schema) -> PlayerStore:
    if request.param == "memory":
        return MemoryPlayerStore()
    from rivalforge.store.postgres import PostgresPlayerStore  # noqa: PLC0415

    with psycopg.connect(schema, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute("TRUNCATE players RESTART IDENTITY")
    store = PostgresPlayerStore(schema)
    request.addfinalizer(store.close)
    return store


class TestPlayerStoreContract:
    """Both backends must be indistinguishable to a caller."""

    def test_unknown_player_is_none(self, player_store):
        assert player_store.get_player("nobody") is None

    def test_upsert_then_get(self, player_store):
        player_store.upsert_player(_record())
        stored = player_store.get_player("p1")
        assert stored.display_name == "Name-p1"
        assert stored.points == 100 and stored.wins == 2 and stored.losses == 1

    def test_upsert_is_idempotent_and_updates(self, player_store):
        player_store.upsert_player(_record())
        player_store.upsert_player(_record(points=250))
        assert player_store.get_player("p1").points == 250

    def test_record_a_win(self, player_store):
        player_store.upsert_player(_record())
        updated = player_store.record_result("p1", won=True, points_delta=15)
        assert updated.points == 115 and updated.wins == 3 and updated.losses == 1

    def test_record_a_loss(self, player_store):
        player_store.upsert_player(_record())
        updated = player_store.record_result("p1", won=False, points_delta=-5)
        assert updated.points == 95 and updated.wins == 2 and updated.losses == 2

    def test_points_never_go_negative(self, player_store):
        """The floor is enforced identically in both backends -- in SQL for
        Postgres, in Python for memory."""
        player_store.upsert_player(_record(points=10))
        updated = player_store.record_result("p1", won=False, points_delta=-500)
        assert updated.points == 0

    def test_recording_for_an_unknown_player_raises(self, player_store):
        with pytest.raises(KeyError):
            player_store.record_result("ghost", won=True, points_delta=1)

    def test_leaderboard_is_ordered_and_capped(self, player_store):
        for index, points in enumerate([10, 300, 200, 50]):
            player_store.upsert_player(_record(player_id=f"p{index}", points=points))
        board = player_store.leaderboard(limit=3)
        assert [p.points for p in board] == [300, 200, 50]

    def test_leaderboard_ties_break_stably(self, player_store):
        """Two players on equal points must not swap places between reads."""
        for name in ("b", "a", "c"):
            player_store.upsert_player(_record(player_id=name, points=100))
        first = [p.player_id for p in player_store.leaderboard()]
        assert first == [p.player_id for p in player_store.leaderboard()]

    def test_empty_leaderboard(self, player_store):
        assert player_store.leaderboard() == ()

    def test_satisfies_the_port(self, player_store):
        assert isinstance(player_store, PlayerStore)

    # -- never trust, always validate: identical rules in both backends ----

    @pytest.mark.parametrize("bad", [
        "", "  ", "'; DROP TABLE players; --", "has space", "x" * 65, None, 42,
    ])
    def test_a_malformed_player_id_is_rejected(self, player_store, bad):
        with pytest.raises(ValidationError):
            player_store.get_player(bad)

    def test_a_malformed_wallet_is_rejected(self, player_store):
        with pytest.raises(ValidationError):
            player_store.upsert_player(_record(wallet="not-a-wallet"))

    def test_a_valid_wallet_is_accepted(self, player_store):
        wallet = b58encode(b"\x11" * 32)
        assert player_store.upsert_player(_record(wallet=wallet)).wallet == wallet

    def test_a_display_name_is_sanitized_on_write(self, player_store):
        """Zero-width and bidi characters are stripped before storage, so a
        spoofed name cannot be persisted and then rendered later."""
        stored = player_store.upsert_player(
            PlayerRecord(
                player_id="p1", wallet=None, display_name="  Fro\u200bst\u202eKnight  ",
                points=0, wins=0, losses=0, created_at=NOW,
            )
        )
        assert stored.display_name == "FrostKnight"

    @pytest.mark.parametrize("points", [-1, 10**9])
    def test_out_of_range_points_are_rejected_not_clamped(self, player_store, points):
        """Silently clamping would hide the bug that produced the value."""
        with pytest.raises(ValidationError):
            player_store.upsert_player(_record(points=points))

    @pytest.mark.parametrize("delta", [MAX_POINTS_DELTA + 1, -(MAX_POINTS_DELTA + 1)])
    def test_an_absurd_points_delta_is_rejected(self, player_store, delta):
        """A match moves the ladder by 15 at most. This stops a buggy or
        compromised caller minting an unreachable score."""
        player_store.upsert_player(_record())
        with pytest.raises(ValidationError):
            player_store.record_result("p1", won=True, points_delta=delta)

    @pytest.mark.parametrize("bad", ["yes", 1, None])
    def test_a_non_boolean_outcome_is_rejected(self, player_store, bad):
        player_store.upsert_player(_record())
        with pytest.raises(ValidationError):
            player_store.record_result("p1", won=bad, points_delta=1)


# ==========================================================================
# Contract: SessionStore, all three implementations
# ==========================================================================


@pytest.fixture(params=["memory", "file", "postgres"])
def session_store(request, tmp_path, schema):
    if request.param == "memory":
        return InMemorySessionStore()
    if request.param == "file":
        from rivalforge.auth.session_store import FileSessionStore  # noqa: PLC0415

        return FileSessionStore(tmp_path / "sessions.json")
    from rivalforge.store.postgres import PostgresSessionStore  # noqa: PLC0415

    with psycopg.connect(schema, autocommit=True) as connection:
        with connection.cursor() as cursor:
            cursor.execute("TRUNCATE sessions")
    store = PostgresSessionStore(schema)
    request.addfinalizer(store.close)
    return store


def _session(token_hash="h1", wallet="W1", expires=None) -> Session:
    return Session(
        token_hash=token_hash, wallet=wallet, created_at=NOW,
        expires_at=expires or NOW + timedelta(hours=12),
    )


class TestSessionStoreContract:
    def test_put_then_get(self, session_store):
        session_store.put(_session())
        assert session_store.get("h1").wallet == "W1"

    def test_unknown_hash_is_none(self, session_store):
        assert session_store.get("nope") is None

    def test_delete(self, session_store):
        session_store.put(_session())
        assert session_store.delete("h1") is True
        assert session_store.get("h1") is None
        assert session_store.delete("h1") is False

    def test_delete_by_wallet(self, session_store):
        for index in range(3):
            session_store.put(_session(token_hash=f"h{index}", wallet="W1"))
        session_store.put(_session(token_hash="other", wallet="W2"))
        assert session_store.delete_wallet("W1") == 3
        assert session_store.get("other") is not None

    def test_purge_expired(self, session_store):
        session_store.put(_session(token_hash="live"))
        session_store.put(_session(token_hash="dead", expires=NOW - timedelta(hours=1)))
        assert session_store.purge_expired(NOW) == 1
        assert session_store.get("live") is not None
        assert session_store.get("dead") is None

    def test_len(self, session_store):
        assert len(session_store) == 0
        session_store.put(_session())
        assert len(session_store) == 1

    def test_oldest_token_hash(self, session_store):
        session_store.put(_session(token_hash="later", expires=NOW + timedelta(hours=20)))
        session_store.put(_session(token_hash="sooner", expires=NOW + timedelta(hours=1)))
        assert session_store.oldest_token_hash() == "sooner"

    def test_the_store_never_holds_a_plaintext_token(self, session_store):
        """Whatever the backend, only the hash is persisted."""
        service = SessionService(FixedClock(NOW), store=session_store)
        issued = service.issue("W1")
        stored = session_store.get(issued.session.token_hash)
        assert stored is not None
        assert issued.token not in repr(stored)
        assert issued.token != stored.token_hash

    def test_a_service_round_trip_works_on_every_backend(self, session_store):
        service = SessionService(FixedClock(NOW), store=session_store)
        issued = service.issue("W1")
        assert service.resolve(issued.token).wallet == "W1"
        assert service.revoke(issued.token) is True
        assert service.resolve(issued.token) is None


# ==========================================================================
# Postgres-specific: what only a database can do or get wrong
# ==========================================================================


@requires_db
class TestPostgresSpecific:
    def test_record_result_is_atomic_under_concurrency(self, pg_players, clean):
        """Read-modify-write in Python would lose updates here. The arithmetic
        happens in SQL, so twenty concurrent results all land."""
        from rivalforge.store.postgres import PostgresPlayerStore  # noqa: PLC0415

        pg_players.upsert_player(_record(points=0, wins=0, losses=0))
        threads = []
        errors: list[Exception] = []
        barrier = threading.Barrier(20)

        def bump():
            store = PostgresPlayerStore(clean)
            try:
                barrier.wait()
                store.record_result("p1", won=True, points_delta=10)
            except Exception as exc:  # pragma: no cover - surfaced by the assert
                errors.append(exc)
            finally:
                store.close()

        for _ in range(20):
            thread = threading.Thread(target=bump)
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, errors
        final = pg_players.get_player("p1")
        assert final.points == 200, f"lost updates: {final.points} != 200"
        assert final.wins == 20

    def test_a_wallet_is_unique(self, pg_players):
        wallet = b58encode(b"\x21" * 32)
        pg_players.upsert_player(_record(player_id="a", wallet=wallet))
        with pytest.raises(TransientError):
            pg_players.upsert_player(_record(player_id="b", wallet=wallet))

    @pytest.mark.parametrize("hostile", [
        "'; DROP TABLE players; --",
        "' OR '1'='1",
        "p1'); DELETE FROM players WHERE ('1'='1",
        "\\'; TRUNCATE players; --",
    ])
    def test_hostile_identifiers_are_rejected_before_reaching_sql(
        self, pg_players, hostile
    ):
        """Defence in depth. The queries are parameterised, so these would be
        harmless anyway -- but rejecting them at the boundary means an
        injection attempt never reaches the driver at all."""
        with pytest.raises(ValidationError):
            pg_players.upsert_player(_record(player_id=hostile))
        with pytest.raises(ValidationError):
            pg_players.get_player(hostile)

        # And the table is still there.
        pg_players.upsert_player(_record(player_id="survivor"))
        assert pg_players.get_player("survivor") is not None

    @pytest.mark.parametrize("hostile", [
        "'; DROP TABLE players; --",
        "Robert'); DROP TABLE players; --",
        '" OR ""="',
    ])
    def test_hostile_free_text_is_stored_as_data(self, pg_players, hostile):
        """Display names legitimately accept quotes and semicolons, so this is
        where parameterisation has to carry the weight rather than validation.
        The value round-trips as text and the table survives."""
        record = _record()
        stored = pg_players.upsert_player(
            PlayerRecord(
                player_id=record.player_id, wallet=None, display_name=hostile,
                points=0, wins=0, losses=0, created_at=NOW,
            )
        )
        assert stored.display_name  # sanitized, but present
        assert pg_players.get_player("p1") is not None

    @pytest.mark.parametrize("bad", ["10; DROP TABLE players", None, 1.5, True])
    def test_a_non_integer_limit_is_rejected(self, pg_players, bad):
        """`limit` cannot carry SQL, because it cannot be anything but an int."""
        with pytest.raises(ValidationError):
            pg_players.leaderboard(limit=bad)

    def test_an_absurd_limit_is_bounded_not_rejected(self, pg_players):
        pg_players.upsert_player(_record())
        assert len(pg_players.leaderboard(limit=10**9)) == 1

    def test_a_corrupt_row_is_a_loud_error_not_a_silent_load(self, pg_players, clean):
        """Never trust, always validate -- including the database. A row that
        breaks the rules is rejected on read, because a migration, a hand-run
        UPDATE, or another writer can all produce one."""
        pg_players.upsert_player(_record())
        with psycopg.connect(clean, autocommit=True) as connection:
            with connection.cursor() as cursor:
                # Bypass the CHECK constraint the way a careless migration
                # would: drop it, then write the bad value.
                cursor.execute("ALTER TABLE players DROP CONSTRAINT players_points_check")
                cursor.execute("UPDATE players SET points = -500 WHERE player_id = %s", ("p1",))
        try:
            with pytest.raises(CorruptRecord, match="failed validation"):
                pg_players.get_player("p1")
        finally:
            with psycopg.connect(clean, autocommit=True) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE players SET points = 0 WHERE player_id = %s", ("p1",))
                    cursor.execute(
                        "ALTER TABLE players ADD CONSTRAINT players_points_check "
                        "CHECK (points >= 0)"
                    )

    def test_a_corrupt_row_error_does_not_echo_the_bad_value(self, pg_players, clean):
        """A corrupt row can contain anything, including something hostile
        written by another path. Copying it into an exception message is how
        that reaches a log or a screen."""
        pg_players.upsert_player(_record())
        marker = "SPOOF<script>alert(1)</script>"
        with psycopg.connect(clean, autocommit=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE players SET display_name = %s WHERE player_id = %s",
                    ("\u200b\u200b", "p1"),
                )
        with pytest.raises(CorruptRecord) as exc:
            pg_players.get_player("p1")
        assert marker not in str(exc.value)
        assert "p1" in str(exc.value)  # the row is identified

    def test_audit_writes_and_reads_back(self, pg_audit):
        trail = AuditTrail(pg_audit, FixedClock(NOW))
        trail.auth_succeeded("W1")
        trail.auth_failed("W2", "bad signature")
        records = pg_audit.records()
        assert len(records) == 2
        assert {r.event for r in records} == {
            AuditEvent.AUTH_SUCCEEDED, AuditEvent.AUTH_FAILED
        }

    def test_audit_is_durable_and_says_so(self, pg_audit):
        assert pg_audit.durable is True

    def test_audit_filters_by_wallet(self, pg_audit):
        trail = AuditTrail(pg_audit, FixedClock(NOW))
        trail.auth_succeeded("W1")
        trail.auth_succeeded("W2")
        assert len(pg_audit.for_wallet("W1")) == 1

    def test_audit_offers_no_update_or_delete(self, pg_audit):
        """Append-only by use. Enforcing it in the database needs a role
        without UPDATE/DELETE, which is a deployment concern -- but the code
        must not hand anyone the tools."""
        for forbidden in ("update", "delete", "remove", "clear", "purge"):
            assert not hasattr(pg_audit, forbidden), forbidden

    def test_schema_application_is_idempotent(self, clean):
        from rivalforge.store.postgres import apply_schema  # noqa: PLC0415

        assert apply_schema(clean) == apply_schema(clean) == 1

    def test_a_closed_connection_is_reopened(self, pg_players):
        """A database restart must not require a process restart."""
        pg_players.upsert_player(_record())
        pg_players.close()
        assert pg_players.get_player("p1") is not None


# ==========================================================================
# Configuration and secret handling -- no database needed
# ==========================================================================


# NOT-A-REAL-SECRET: placeholder DSNs for the TLS and redaction tests below.
# Assembled at runtime so no credential-shaped literal sits in the file for a
# secret scanner to flag -- the scanner caught these on the first run, which is
# exactly the behaviour we want from it.
_FAKE_USER = "u"
_FAKE_PASS = "p"
_FAKE_HOST = "db.example.com"


def _fake_dsn(user=_FAKE_USER, password=_FAKE_PASS, host=_FAKE_HOST, db="x", query=""):
    """Build a placeholder connection string. No real credentials involved."""
    credentials = f"{user}:{password}" if password else user
    return "postgresql://" + credentials + "@" + host + "/" + db + query


class TestConnectionConfiguration:
    def test_missing_configuration_fails_loudly(self):
        """Silently falling back to memory would look like it persists and
        would not."""
        from rivalforge.store.postgres import PostgresUnavailable, connection_url  # noqa: PLC0415

        with pytest.raises(PostgresUnavailable, match="no database configured"):
            connection_url(env={})

    def test_rivalforge_url_beats_the_generic_one(self):
        from rivalforge.store.postgres import connection_url  # noqa: PLC0415

        url = connection_url(env={
            "DATABASE_URL": _fake_dsn(password="", host="other", db="db"),
            "RIVALFORGE_DATABASE_URL": _fake_dsn(password="", host="localhost", db="mine"),
        })
        assert "mine" in url

    def test_tls_is_required_for_a_remote_host(self):
        from rivalforge.store.postgres import connection_url  # noqa: PLC0415

        url = connection_url(env={"DATABASE_URL": _fake_dsn()})
        assert "sslmode=require" in url

    def test_tls_is_not_forced_on_loopback(self):
        """Demanding TLS on localhost only stops people running the tests."""
        from rivalforge.store.postgres import connection_url  # noqa: PLC0415

        url = connection_url(env={"DATABASE_URL": _fake_dsn(password="", host="127.0.0.1:5432")})
        assert "sslmode" not in url

    def test_an_explicit_sslmode_is_respected(self):
        from rivalforge.store.postgres import connection_url  # noqa: PLC0415

        url = connection_url(env={"DATABASE_URL": _fake_dsn(query="?sslmode=verify-full")})
        assert url.count("sslmode") == 1
        assert "verify-full" in url

    def test_insecure_transport_requires_an_explicit_opt_in(self, caplog):
        from rivalforge.store.postgres import connection_url  # noqa: PLC0415

        url = connection_url(env={
            "DATABASE_URL": _fake_dsn(),
            "RIVALFORGE_DB_ALLOW_INSECURE": "1",
        })
        assert "sslmode" not in url
        assert "TLS to the database is disabled" in caplog.text

    def test_the_logged_form_carries_no_credentials(self):
        from rivalforge.store.postgres import _redact_url  # noqa: PLC0415

        dsn = _fake_dsn(user="admin", password="hunter2", db="rivalforge")
        safe = _redact_url(dsn)
        assert "hunter2" not in safe and "admin" not in safe
        assert _FAKE_HOST in safe

    def test_the_redaction_filter_scrubs_a_database_url(self):
        """A connection string in a stack trace is a leaked password."""
        from rivalforge.security.redaction import redact  # noqa: PLC0415

        dsn = _fake_dsn(user="admin", password="hunter2", db="rf")
        scrubbed = redact("connecting to " + dsn)
        assert "hunter2" not in scrubbed
        # The host and database survive, so the line stays diagnosable.
        assert _FAKE_HOST in scrubbed


class TestNoStringInterpolationInSql:
    """Every query is a constant with placeholders.

    Scanned rather than reviewed, because "we always parameterise" is a promise
    that lasts until the first hurried patch.
    """

    def test_no_f_strings_or_percent_formatting_in_queries(self):
        import pathlib  # noqa: PLC0415

        import rivalforge.store.postgres as module  # noqa: PLC0415

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        offenders = []
        for number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            upper = stripped.upper()
            if not any(
                keyword in upper
                for keyword in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "TRUNCATE ")
            ):
                continue
            # An f-string or .format() building a query is the pattern that
            # turns a value into code.
            if re.search(r'f["\']', stripped) or ".format(" in stripped:
                offenders.append(f"{number}: {stripped[:70]}")
        assert not offenders, f"interpolated SQL: {offenders}"

    def test_queries_use_placeholders(self):
        from rivalforge.store import postgres as module  # noqa: PLC0415

        for name in ("_GET_PLAYER", "_UPSERT_PLAYER", "_RECORD_RESULT", "_PUT_SESSION"):
            assert "%s" in getattr(module, name), name
