"""The registries themselves, and the wiring that selects an adapter.

One module so there is a single answer to "what can be swapped here?".

Selection is by configuration, never by import. A caller asks for
`wallet_provider(settings)` and gets whatever `RIVALFORGE_WALLET_PROVIDER`
names, with a safe default when nothing is configured. Adding a provider means
publishing a package with an entry point -- no change here.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Mapping

from .ports import (
    Clock,
    NFTOwnershipProvider,
    Notifier,
    PaymentProvider,
    PlayerStore,
)
from .registry import Registry
from .toggles import Toggles

__all__ = [
    "AGENTS",
    "WALLET_PROVIDERS",
    "PLAYER_STORES",
    "NOTIFIERS",
    "PAYMENT_PROVIDERS",
    "CLOCKS",
    "select",
    "wallet_provider",
]

logger = logging.getLogger(__name__)

#: Anything that can play a side: scripted, human-driven, or an LLM.
AGENTS: Registry[Any] = Registry("agent", "rivalforge.agents")

#: Reads NFT ownership. Read-only by contract -- see ports.NFTOwnershipProvider.
WALLET_PROVIDERS: Registry[type[NFTOwnershipProvider]] = Registry(
    "wallet provider", "rivalforge.wallet_providers"
)

#: Persists players and ladders.
PLAYER_STORES: Registry[type[PlayerStore]] = Registry(
    "player store", "rivalforge.player_stores"
)

#: Delivers messages to players.
NOTIFIERS: Registry[type[Notifier]] = Registry("notifier", "rivalforge.notifiers")

#: Takes money. Registered but off behind the `payments` toggle by default.
PAYMENT_PROVIDERS: Registry[type[PaymentProvider]] = Registry(
    "payment provider", "rivalforge.payment_providers"
)

#: Wall-clock time, so daily rotations are testable.
CLOCKS: Registry[type[Clock]] = Registry("clock", "rivalforge.clocks")


#: Environment variable naming the adapter for each registry, and the fallback
#: used when nothing is configured. Every default is inert: no network, no
#: money, no writes. A fresh deployment with no configuration must be safe.
_SELECTION: Mapping[str, tuple[Registry[Any], str, str]] = {
    "wallet": (WALLET_PROVIDERS, "RIVALFORGE_WALLET_PROVIDER", "null"),
    "player_store": (PLAYER_STORES, "RIVALFORGE_PLAYER_STORE", "memory"),
    "notifier": (NOTIFIERS, "RIVALFORGE_NOTIFIER", "null"),
    "payments": (PAYMENT_PROVIDERS, "RIVALFORGE_PAYMENT_PROVIDER", "null"),
    "clock": (CLOCKS, "RIVALFORGE_CLOCK", "system"),
}


def select(kind: str, *, env: Mapping[str, str] | None = None) -> Any:
    """Return the class configured for `kind`.

    Raises:
        KeyError: for an unknown `kind` (a programming error).
        UnknownPlugin: if the configured name is not registered, listing what
            is -- so a bad environment variable is actionable rather than a
            stack trace about a missing key.
    """
    if kind not in _SELECTION:
        raise KeyError(f"unknown selectable {kind!r}; known: {', '.join(sorted(_SELECTION))}")
    registry, env_var, fallback = _SELECTION[kind]
    environment = os.environ if env is None else env
    name = environment.get(env_var, "").strip() or fallback
    return registry.get(name)


def wallet_provider(
    toggles: Toggles, *, env: Mapping[str, str] | None = None, **kwargs: Any
) -> NFTOwnershipProvider:
    """Build the configured NFT ownership provider.

    When `wallet_verification` is off, this returns the null provider whatever
    is configured. That is deliberate: the toggle is the authority on whether
    the game talks to a chain at all, and a stale environment variable must not
    be able to switch on network traffic that the operator turned off.
    """
    from .adapters import NullWalletProvider  # noqa: PLC0415 -- avoids a cycle

    if not toggles.enabled("wallet_verification"):
        return NullWalletProvider()

    provider_class = select("wallet", env=env)
    return provider_class(**kwargs)


def _register_builtins() -> None:
    """Register the adapters that ship with the package.

    Imported for the side effect. Kept in a function so the import order is
    explicit rather than depending on which module someone happened to touch
    first.
    """
    from . import adapters  # noqa: F401,PLC0415

    from ..agents import builtin  # noqa: F401,PLC0415


_register_builtins()
