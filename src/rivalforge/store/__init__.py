"""Durable storage adapters.

Kept in its own package because it is the only part of the codebase with a
third-party runtime dependency (`psycopg`). Importing it is opt-in, so the
engine stays dependency-free and a deployment that does not persist anything
never loads a database driver.
"""

from .postgres import (
    PostgresAuditSink,
    PostgresPlayerStore,
    PostgresSessionStore,
    PostgresUnavailable,
    apply_schema,
    connection_url,
)

__all__ = [
    "PostgresAuditSink",
    "PostgresPlayerStore",
    "PostgresSessionStore",
    "PostgresUnavailable",
    "apply_schema",
    "connection_url",
]
