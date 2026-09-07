"""A typed plugin registry with third-party discovery.

Everything swappable in this codebase goes through a registry: agents, NFT
ownership providers, storage backends, payment providers, notifiers. Adding a
capability means registering an implementation, never editing a dispatch table
buried in a caller.

Two ways in:

*   **In-process** -- decorate a class with `@registry.register("name")`. This
    is how the built-ins register themselves.
*   **Out-of-process** -- a separate distribution declares a Python entry point
    in the registry's group, and `discover()` picks it up with no change to
    this codebase at all::

        [project.entry-points."rivalforge.agents"]
        my_agent = "my_package.agents:MyAgent"

Why a registry rather than `if provider == "helius": ...`:

The previous codebase hardcoded its choices, so replacing the Solana RPC layer
meant editing thirty call sites, and nobody ever did. A registry makes the
replaceable thing a configuration value.

Two rules the registry enforces, because both were real failure modes:

1.  **A name may only be registered once.** Silent override means the plugin
    that happens to import last wins, which is a bug you debug at 3am.
2.  **An unknown name lists what is available.** A `KeyError` with no context
    tells a Lab operator nothing about what they typed wrong.
"""

from __future__ import annotations

import logging
from importlib import metadata
from typing import Callable, Generic, Iterator, TypeVar

__all__ = ["Registry", "RegistryError", "DuplicateRegistration", "UnknownPlugin"]

logger = logging.getLogger(__name__)

T = TypeVar("T")


class RegistryError(RuntimeError):
    """Base class for registry problems."""


class DuplicateRegistration(RegistryError):
    """Raised when a name is registered twice.

    Never a warning. Two implementations claiming one name means one of them is
    silently unreachable, and which one depends on import order.
    """


class UnknownPlugin(RegistryError, KeyError):
    """Raised when a name is requested that nothing registered.

    Subclasses `KeyError` so existing `except KeyError` callers keep working,
    while carrying a message that names the alternatives.
    """

    def __str__(self) -> str:  # KeyError's repr adds quotes; drop them
        return self.args[0] if self.args else ""


class Registry(Generic[T]):
    """A named collection of interchangeable implementations.

    Args:
        name: What this registry holds, for error messages ("agent", "wallet
            provider").
        entry_point_group: The setuptools entry-point group third-party
            packages use to plug in. `None` disables external discovery, which
            is right for registries that must stay closed.
    """

    __slots__ = ("_name", "_group", "_items", "_discovered")

    def __init__(self, name: str, entry_point_group: str | None = None) -> None:
        self._name = name
        self._group = entry_point_group
        self._items: dict[str, T] = {}
        self._discovered = False

    # -- registration ----------------------------------------------------

    def register(self, name: str, value: T | None = None) -> T | Callable[[T], T]:
        """Register `value` under `name`.

        Usable directly or as a decorator::

            registry.register("random", RandomAgent)

            @registry.register("random")
            class RandomAgent: ...
        """
        if value is None:
            def decorator(inner: T) -> T:
                self.register(name, inner)
                return inner

            return decorator

        if not name or not isinstance(name, str):
            raise RegistryError(f"{self._name} name must be a non-empty string, got {name!r}")
        if name in self._items:
            raise DuplicateRegistration(
                f"{self._name} {name!r} is already registered as "
                f"{self._items[name]!r}; names must be unique"
            )
        self._items[name] = value
        return value

    def unregister(self, name: str) -> None:
        """Remove a registration. Mainly for tests; harmless in production."""
        self._items.pop(name, None)

    # -- discovery -------------------------------------------------------

    def discover(self, *, force: bool = False) -> None:
        """Load third-party implementations from the entry-point group.

        A plugin that fails to import is logged and skipped rather than taking
        the process down: one broken third-party package should not stop the
        game from starting. A plugin that imports but clashes on a name is a
        different matter and still raises -- that is an ambiguity, not a
        degraded feature.
        """
        if self._group is None or (self._discovered and not force):
            return
        self._discovered = True

        try:
            entry_points = metadata.entry_points(group=self._group)
        except Exception:  # pragma: no cover - importlib.metadata unavailable
            logger.warning("could not read entry points for %s", self._group, exc_info=True)
            return

        for entry_point in entry_points:
            if entry_point.name in self._items:
                raise DuplicateRegistration(
                    f"{self._name} {entry_point.name!r} from {entry_point.value} "
                    f"clashes with a built-in of the same name"
                )
            try:
                self.register(entry_point.name, entry_point.load())
            except DuplicateRegistration:
                raise
            except Exception:
                logger.warning(
                    "skipping %s plugin %r: it failed to load",
                    self._name, entry_point.name, exc_info=True,
                )

    # -- lookup ----------------------------------------------------------

    def get(self, name: str) -> T:
        """Look up an implementation by name.

        Raises:
            UnknownPlugin: naming what is available, so a misconfigured Lab
                gets an actionable message rather than a bare KeyError.
        """
        self.discover()
        try:
            return self._items[name]
        except KeyError:
            available = ", ".join(sorted(self._items)) or "(nothing registered)"
            raise UnknownPlugin(
                f"unknown {self._name} {name!r}; available: {available}"
            ) from None

    def names(self) -> tuple[str, ...]:
        """Every registered name, sorted."""
        self.discover()
        return tuple(sorted(self._items))

    def __contains__(self, name: object) -> bool:
        self.discover()
        return name in self._items

    def __iter__(self) -> Iterator[tuple[str, T]]:
        self.discover()
        return iter(sorted(self._items.items()))

    def __len__(self) -> int:
        self.discover()
        return len(self._items)

    def __repr__(self) -> str:
        return f"<Registry {self._name!r} with {len(self._items)} entries>"
