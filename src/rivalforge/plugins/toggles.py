"""Feature toggles.

Every feature that can be off is off behind a named toggle, resolved from
configuration rather than code. Turning a feature on is an environment change,
not a deploy of a different build.

Resolution order, first match wins:

1.  an explicit override passed in process (tests, one-off scripts);
2.  the environment, as ``RIVALFORGE_FEATURE_<NAME>``;
3.  a JSON config file named by ``RIVALFORGE_FEATURES_FILE``;
4.  the toggle's declared default.

Two deliberate design choices:

*   **Toggles are declared, not invented.** Asking for an undeclared toggle
    raises. A typo'd flag name that silently reads false is a feature that is
    off in production and on in your head -- the previous codebase had a
    toggle system with exactly that hole.
*   **The default is safe.** Anything touching money, chain writes, or a
    third-party service defaults to off, so a fresh deployment with no
    configuration is inert rather than surprising.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Mapping

__all__ = ["Toggle", "Toggles", "FEATURES", "toggles", "UnknownToggle"]

logger = logging.getLogger(__name__)

ENV_PREFIX: Final = "RIVALFORGE_FEATURE_"
ENV_FILE: Final = "RIVALFORGE_FEATURES_FILE"

_TRUE: Final = frozenset({"1", "true", "yes", "on", "enabled"})
_FALSE: Final = frozenset({"0", "false", "no", "off", "disabled", ""})


class UnknownToggle(KeyError):
    """Raised when code asks for a toggle nobody declared."""

    def __str__(self) -> str:
        return self.args[0] if self.args else ""


@dataclass(frozen=True, slots=True)
class Toggle:
    """A declared feature flag."""

    name: str
    default: bool
    description: str

    @property
    def env_var(self) -> str:
        return f"{ENV_PREFIX}{self.name.upper()}"


#: Every toggle in the system. Adding a feature means adding a line here, which
#: makes this the one place to look to know what the build can do.
FEATURES: Final[tuple[Toggle, ...]] = (
    Toggle(
        "wallet_verification",
        default=False,
        description=(
            "Verify on-chain that a player owns the NFT they are playing. "
            "Off by default: it needs a configured RPC provider, and without "
            "one the game must fall back to unverified play, not to an error."
        ),
    ),
    Toggle(
        "ai_agents",
        default=True,
        description="Allow scripted agents to take a side in a match.",
    ),
    Toggle(
        "persistence",
        default=False,
        description="Store players, ladders and match results. Off until a backend is configured.",
    ),
    Toggle(
        "telegram_bot",
        default=False,
        description="Serve the game over Telegram. Needs a bot token.",
    ),
    Toggle(
        "payments",
        default=False,
        description="Accept payment for extra runs and cosmetics. Off by default: it moves money.",
    ),
    Toggle(
        "sponsorships",
        default=False,
        description="Brand-funded prize pools and fighter sponsorship deals.",
    ),
    Toggle(
        "daily_boss",
        default=False,
        description="A shared global boss with a pooled reward.",
    ),
    Toggle(
        "temporal_boss",
        default=False,
        description="Yesterday's top player becomes today's boss.",
    ),
)

_BY_NAME: Final[Mapping[str, Toggle]] = {t.name: t for t in FEATURES}


def _coerce(raw: str, *, source: str, name: str) -> bool | None:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    logger.warning(
        "ignoring %s for toggle %r: %r is not a boolean", source, name, raw
    )
    return None


class Toggles:
    """Resolved feature toggles.

    Construct once at start-up and pass it down. Reading the environment on
    every check would let a feature flip mid-match, which is exactly the kind
    of inconsistency that produces unreproducible bug reports.
    """

    __slots__ = ("_resolved", "_overrides")

    def __init__(
        self,
        overrides: Mapping[str, bool] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        environment = os.environ if env is None else env
        self._overrides = dict(overrides or {})

        for name in self._overrides:
            if name not in _BY_NAME:
                raise UnknownToggle(
                    f"unknown toggle {name!r}; declared: {', '.join(sorted(_BY_NAME))}"
                )

        from_file = self._load_file(environment)
        resolved: dict[str, bool] = {}

        for toggle in FEATURES:
            if toggle.name in self._overrides:
                resolved[toggle.name] = self._overrides[toggle.name]
                continue

            raw_env = environment.get(toggle.env_var)
            if raw_env is not None:
                value = _coerce(raw_env, source=toggle.env_var, name=toggle.name)
                if value is not None:
                    resolved[toggle.name] = value
                    continue

            if toggle.name in from_file:
                resolved[toggle.name] = from_file[toggle.name]
                continue

            resolved[toggle.name] = toggle.default

        self._resolved = resolved

    @staticmethod
    def _load_file(env: Mapping[str, str]) -> dict[str, bool]:
        path_name = env.get(ENV_FILE)
        if not path_name:
            return {}
        path = Path(path_name)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # A missing or malformed toggle file must not stop the game. The
            # declared defaults are safe, so degrade to them and say so.
            logger.warning("could not read toggle file %s; using defaults", path, exc_info=True)
            return {}
        if not isinstance(raw, dict):
            logger.warning("toggle file %s is not a JSON object; using defaults", path)
            return {}

        out: dict[str, bool] = {}
        for name, value in raw.items():
            if name not in _BY_NAME:
                logger.warning("toggle file names an unknown toggle %r; ignoring", name)
                continue
            if isinstance(value, bool):
                out[name] = value
            elif isinstance(value, str):
                coerced = _coerce(value, source=str(path), name=name)
                if coerced is not None:
                    out[name] = coerced
            else:
                logger.warning("toggle %r in %s is not a boolean; ignoring", name, path)
        return out

    def enabled(self, name: str) -> bool:
        """Whether `name` is on.

        Raises:
            UnknownToggle: if nothing declared `name`. A typo must not read as
                a quietly disabled feature.
        """
        try:
            return self._resolved[name]
        except KeyError:
            raise UnknownToggle(
                f"unknown toggle {name!r}; declared: {', '.join(sorted(_BY_NAME))}"
            ) from None

    def require(self, name: str) -> None:
        """Raise unless `name` is on. For code paths that must not run when off."""
        if not self.enabled(name):
            raise RuntimeError(
                f"feature {name!r} is disabled; enable it with "
                f"{_BY_NAME[name].env_var}=1"
            )

    def as_dict(self) -> dict[str, bool]:
        return dict(self._resolved)

    def describe(self) -> str:
        """A human-readable report, for a `--features` flag or a health check."""
        width = max(len(t.name) for t in FEATURES)
        lines = []
        for toggle in FEATURES:
            state = "on " if self._resolved[toggle.name] else "off"
            lines.append(f"  {state}  {toggle.name:<{width}}  {toggle.description}")
        return "\n".join(lines)


def toggles(**overrides: bool) -> Toggles:
    """Build a `Toggles` from the environment, with optional overrides."""
    return Toggles(overrides=overrides or None)
