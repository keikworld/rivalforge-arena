"""Where sessions live.

A port, because the right answer differs by deployment and none of them should
require editing `SessionService`:

* **memory** -- one process, nothing survives a restart. Correct for tests.
* **file** -- one machine, survives restarts. Correct for the CLI, where
  `connect` and `play` are separate processes and a session that did not
  outlive one of them would make the tool unusable.
* **postgres** -- many processes. Phase 2's persistence work.

Whatever the backend, one invariant holds everywhere: **the store never holds a
session token.** It holds SHA-256 of the token. A stolen store yields no live
sessions, so the blast radius of a file leak or a database dump is bounded to
"an attacker learns which wallets played recently" rather than "an attacker is
those players".
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from ..plugins.registry import Registry

logger = logging.getLogger(__name__)

__all__ = [
    "SessionStore",
    "InMemorySessionStore",
    "FileSessionStore",
    "SESSION_STORES",
]

SESSION_STORES: Registry[type] = Registry("session store", "rivalforge.session_stores")

#: Ceiling for the file store. A session file that grows without bound is a
#: disk-exhaustion bug waiting for an attacker who can authenticate repeatedly.
_MAX_FILE_SESSIONS: Final = 5_000


@runtime_checkable
class SessionStore(Protocol):
    """Storage for live sessions, keyed by token hash."""

    name: str

    def put(self, session) -> None:
        ...

    def get(self, token_hash: str):
        ...

    def delete(self, token_hash: str) -> bool:
        ...

    def delete_wallet(self, wallet: str) -> int:
        ...

    def purge_expired(self, now: datetime) -> int:
        ...

    def __len__(self) -> int:
        ...


@SESSION_STORES.register("memory")
class InMemorySessionStore:
    """Process-local. Fast, and gone on restart."""

    name = "memory"

    __slots__ = ("_sessions", "_lock")

    def __init__(self) -> None:
        self._sessions: dict[str, object] = {}
        self._lock = threading.Lock()

    def put(self, session) -> None:
        with self._lock:
            self._sessions[session.token_hash] = session

    def get(self, token_hash: str):
        with self._lock:
            return self._sessions.get(token_hash)

    def delete(self, token_hash: str) -> bool:
        with self._lock:
            return self._sessions.pop(token_hash, None) is not None

    def delete_wallet(self, wallet: str) -> int:
        with self._lock:
            doomed = [h for h, s in self._sessions.items() if s.wallet == wallet]
            for digest in doomed:
                del self._sessions[digest]
            return len(doomed)

    def purge_expired(self, now: datetime) -> int:
        with self._lock:
            stale = [h for h, s in self._sessions.items() if s.is_expired(now)]
            for digest in stale:
                del self._sessions[digest]
            return len(stale)

    def oldest_token_hash(self) -> str | None:
        with self._lock:
            if not self._sessions:
                return None
            return min(self._sessions.items(), key=lambda kv: kv[1].expires_at)[0]

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


@SESSION_STORES.register("file")
class FileSessionStore:
    """A JSON file, owner-readable only.

    For single-machine use. Every write is atomic (write a temporary file in
    the same directory, then rename) so a crash mid-write cannot leave a
    truncated file that logs everyone out.

    The file is created 0600 from the outset rather than chmod-ed afterwards --
    otherwise the contents are briefly world-readable, which is a real window on
    a shared machine.
    """

    name = "file"

    __slots__ = ("_path", "_lock", "_max")

    def __init__(self, path: str | Path, *, max_sessions: int = _MAX_FILE_SESSIONS) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._max = max_sessions
        self._path.parent.mkdir(parents=True, exist_ok=True)

    # -- persistence --------------------------------------------------

    def _read(self) -> dict[str, dict]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            # A corrupt session file logs everyone out; it must never crash the
            # program. Failing closed here is the safe direction.
            logger.warning("session file %s unreadable; starting empty", self._path)
            return {}
        return raw if isinstance(raw, dict) else {}

    def _write(self, data: dict[str, dict]) -> None:
        temporary = self._path.with_suffix(".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(data, handle)
            os.replace(temporary, self._path)  # atomic
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _to_row(session) -> dict:
        return {
            "wallet": session.wallet,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
        }

    @staticmethod
    def _from_row(token_hash: str, row: dict):
        from .session import Session  # noqa: PLC0415 -- avoids an import cycle

        return Session(
            token_hash=token_hash,
            wallet=row["wallet"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    # -- port ----------------------------------------------------------

    def put(self, session) -> None:
        with self._lock:
            data = self._read()
            if len(data) >= self._max:
                now = datetime.now(timezone.utc)
                data = {
                    h: r for h, r in data.items()
                    if datetime.fromisoformat(r["expires_at"]) > now
                }
                if len(data) >= self._max:
                    oldest = min(data.items(), key=lambda kv: kv[1]["expires_at"])[0]
                    del data[oldest]
            data[session.token_hash] = self._to_row(session)
            self._write(data)

    def get(self, token_hash: str):
        with self._lock:
            row = self._read().get(token_hash)
            if row is None:
                return None
            try:
                return self._from_row(token_hash, row)
            except (KeyError, ValueError):
                return None

    def delete(self, token_hash: str) -> bool:
        with self._lock:
            data = self._read()
            if data.pop(token_hash, None) is None:
                return False
            self._write(data)
            return True

    def delete_wallet(self, wallet: str) -> int:
        with self._lock:
            data = self._read()
            doomed = [h for h, r in data.items() if r.get("wallet") == wallet]
            for digest in doomed:
                del data[digest]
            if doomed:
                self._write(data)
            return len(doomed)

    def purge_expired(self, now: datetime) -> int:
        with self._lock:
            data = self._read()
            stale = [
                h for h, r in data.items()
                if datetime.fromisoformat(r["expires_at"]) <= now
            ]
            for digest in stale:
                del data[digest]
            if stale:
                self._write(data)
            return len(stale)

    def oldest_token_hash(self) -> str | None:
        with self._lock:
            data = self._read()
            if not data:
                return None
            return min(data.items(), key=lambda kv: kv[1]["expires_at"])[0]

    def __len__(self) -> int:
        with self._lock:
            return len(self._read())
