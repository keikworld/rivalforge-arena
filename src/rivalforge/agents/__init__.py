"""Agents that can play a side. Same interface as a human at a prompt."""

from .builtin import (
    AGENT_REGISTRY,
    AdaptiveAgent,
    AggressiveAgent,
    DefensiveAgent,
    RandomAgent,
    build_agent,
)

__all__ = [
    "AGENT_REGISTRY", "AdaptiveAgent", "AggressiveAgent", "DefensiveAgent",
    "RandomAgent", "build_agent",
]
