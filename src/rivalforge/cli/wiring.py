"""Composition root: the one place that builds the object graph.

Every dependency is chosen here, from configuration, and passed down. Nothing
below this module constructs its own collaborators, which is what keeps the
core testable and the adapters swappable.

It is also the security choke point. There is exactly one place that decides
whether ownership is enforced, which wallet provider is live, and where the
audit trail goes -- so there is exactly one place to read to know what a
deployment actually does.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Final, Mapping

from ..auth.audit import AuditTrail, InMemoryAuditSink
from ..auth.challenge import ChallengeService
from ..auth.service import WalletService
from ..auth.session import SessionService
from ..auth.session_store import FileSessionStore, InMemorySessionStore
from ..auth.store import InMemoryChallengeStore
from ..content.loader import load_content
from ..content.schema import GameContent
from ..plugins.registries import select, wallet_provider
from ..plugins.toggles import Toggles, toggles

logger = logging.getLogger(__name__)

__all__ = ["Application", "build_application", "DEFAULT_DOMAIN", "DEFAULT_URI"]

DEFAULT_DOMAIN: Final = "rivalforge.local"
DEFAULT_URI: Final = "https://rivalforge.local"


def _default_session_path(env: Mapping[str, str]):
    """Where session state lives when nothing is configured.

    Under XDG state, not the working directory: a session file dropped into a
    repository is a file that eventually gets committed.
    """
    from pathlib import Path  # noqa: PLC0415

    base = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "rivalforge" / "sessions.json"


@dataclass(frozen=True, slots=True)
class Application:
    """Everything a front end needs, already wired."""

    content: GameContent
    features: Toggles
    wallets: WalletService
    audit_sink: object
    clock: object
    players: object | None = None

    def describe(self) -> str:
        """A start-up banner an operator can read to know what is live."""
        provider = getattr(self.wallets, "_ownership", None)
        return (
            f"  wallet verification : "
            f"{'on' if self.features.enabled('wallet_verification') else 'off'}\n"
            f"  wallet provider     : {getattr(provider, 'name', type(provider).__name__)}\n"
            f"  ownership enforced  : "
            f"{'yes' if getattr(self.wallets, '_require_ownership', True) else 'NO'}\n"
            f"  audit sink          : {getattr(self.audit_sink, 'name', '?')} "
            f"({'durable' if getattr(self.audit_sink, 'durable', False) else 'in memory, lost on restart'})\n"
            f"  persistence         : "
            + (
                f"postgres ({self.players.dsn_for_logging})"
                if self.players is not None
                else "off (players and ladder are not saved)"
            )
        )


def build_application(
    *,
    env: Mapping[str, str] | None = None,
    overrides: Mapping[str, bool] | None = None,
) -> Application:
    """Build the application from configuration.

    Args:
        env: Environment to read. Defaults to the real one.
        overrides: Feature toggle overrides, for tests and one-off commands.
    """
    environment = os.environ if env is None else env
    features = Toggles(overrides=dict(overrides or {}), env=environment)

    clock = select("clock", env=environment)()
    content = load_content()

    domain = environment.get("RIVALFORGE_DOMAIN", DEFAULT_DOMAIN)
    uri = environment.get("RIVALFORGE_URI", DEFAULT_URI)
    cluster = environment.get("RIVALFORGE_CLUSTER", "mainnet")

    challenges = ChallengeService(
        InMemoryChallengeStore(), clock, domain=domain, uri=uri, cluster=cluster
    )

    # Sessions must outlive one process: in the CLI, `connect` and `play` are
    # separate invocations, and a memory-only store would make a session
    # useless the moment it was issued. The file store keeps the token *hash*
    # only, owner-readable, so a leak of it yields no live session.
    session_path = environment.get("RIVALFORGE_SESSION_FILE")
    if session_path:
        session_store = FileSessionStore(session_path)
    else:
        session_store = FileSessionStore(_default_session_path(environment))
    audit_sink = InMemoryAuditSink()
    players = None

    # Persistence is opt-in and fails loudly. Silently falling back to memory
    # when a database was configured would look like it persists and would not.
    if features.enabled("persistence"):
        try:
            from ..store.postgres import (  # noqa: PLC0415
                PostgresAuditSink,
                PostgresPlayerStore,
                PostgresSessionStore,
                apply_schema,
                connection_url,
            )

            url = connection_url(environment)
            apply_schema(url)
            session_store = PostgresSessionStore(url)
            audit_sink = PostgresAuditSink(url)
            players = PostgresPlayerStore(url)
            logger.info("persistence enabled: %s", players.dsn_for_logging)
        except Exception:
            logger.exception("persistence is enabled but the database is unreachable")
            raise

    sessions = SessionService(clock, store=session_store)
    ownership = wallet_provider(features, env=environment)

    # Ownership enforcement follows the same toggle as verification. With
    # verification off there is nothing to enforce *with*, and pretending
    # otherwise would reject every player rather than letting them play
    # unverified -- which is the intended behaviour of the toggle being off.
    require_ownership = features.enabled("wallet_verification")
    if not require_ownership:
        logger.info("wallet verification is off; NFT ownership will not be enforced")

    wallets = WalletService(
        challenges,
        sessions,
        ownership,
        AuditTrail(audit_sink, clock),
        content,
        require_ownership=require_ownership,
    )

    return Application(
        content=content,
        features=features,
        wallets=wallets,
        audit_sink=audit_sink,
        clock=clock,
        players=players,
    )
