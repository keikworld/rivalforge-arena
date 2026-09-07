"""Built-in agents.

An agent is anything with `decide(view) -> Decision`. That is the entire
interface, and it is the same one a human terminal prompt implements, so
AI-vs-AI needed no separate code path.

Every agent here is deterministic given its RNG, so an agent-vs-agent
tournament is reproducible from a single seed -- which is what makes these
usable as a balance harness rather than only as opponents.

Deliberately no LLM agent yet. The interface is ready for one (`decide` takes a
view and returns a validated decision, so a model's output is checked exactly
like a player's), but adding it belongs in a phase where its latency, cost and
prompt-injection surface get proper attention. See docs/ROADMAP.md.
"""

from __future__ import annotations

from collections import Counter
from typing import Mapping

from ..content.schema import Stance, beats
from ..engine.match import Decision, MatchView, SupportsDecide
from ..engine.rng import RNG
from ..plugins.registries import AGENTS

__all__ = [
    "RandomAgent",
    "AggressiveAgent",
    "DefensiveAgent",
    "AdaptiveAgent",
    "AGENT_REGISTRY",
    "build_agent",
]

#: What each stance loses to. Picking the counter to a predicted stance is the
#: whole of the tactical layer, so it is written once, here.
_COUNTER: dict[Stance, Stance] = {
    Stance.STRIKE: Stance.GUARD,
    Stance.GUARD: Stance.FOCUS,
    Stance.FOCUS: Stance.STRIKE,
}


class RandomAgent(SupportsDecide):
    """Picks uniformly. The baseline every other agent must beat."""

    name = "random"

    def __init__(self, rng: RNG) -> None:
        self._rng = rng

    def decide(self, view: MatchView) -> Decision:
        stance = self._rng.choice(tuple(Stance))
        return Decision(stance=stance, spend_soul=view.can_spend_soul)


class AggressiveAgent(SupportsDecide):
    """Strikes almost always, and only builds Soul when it is losing badly.

    Beats passive opponents and loses to anyone who reads it. Exists to make
    sure GUARD has something to punish.
    """

    name = "aggressive"

    def __init__(self, rng: RNG) -> None:
        self._rng = rng

    def decide(self, view: MatchView) -> Decision:
        losing_badly = view.your_bp < view.opponent_bp * 0.5
        if losing_badly and not view.can_spend_soul and self._rng.chance(0.5):
            return Decision(stance=Stance.FOCUS)
        if self._rng.chance(0.15):
            return Decision(stance=Stance.GUARD, spend_soul=view.can_spend_soul)
        return Decision(stance=Stance.STRIKE, spend_soul=view.can_spend_soul)


class DefensiveAgent(SupportsDecide):
    """A counter-puncher: absorbs, banks Soul, and closes when the opening comes.

    An earlier version only guarded and focused. It never attacked, so it had
    no win condition, and measurement put it at a 9% overall win rate -- 1.7%
    against the aggressive agent. That is not a defensive playstyle, it is a
    punching bag, and it made the agent useless as a benchmark.

    The fix is a finisher clause. It still plays for the arena mechanic, but it
    takes the kill when one is available and stops conceding free rounds once
    its Soul is capped.
    """

    name = "defensive"

    #: Opponent BP at which winning the race beats playing for the mechanic.
    FINISH_THRESHOLD = 34

    def __init__(self, rng: RNG) -> None:
        self._rng = rng

    def decide(self, view: MatchView) -> Decision:
        if view.can_spend_soul:
            return Decision(stance=Stance.GUARD, spend_soul=True)

        # Close it out rather than politely building resources to the end.
        if view.opponent_bp <= self.FINISH_THRESHOLD:
            return Decision(stance=Stance.STRIKE)

        # Banking Soul is only worth a weak round while there is Soul to bank.
        if view.your_souls < view.arena.soul_cost:
            return Decision(stance=Stance.FOCUS)

        # Capped on Soul but short of the cost: guarding forever is a slow
        # loss, so mix in real pressure.
        return Decision(stance=Stance.STRIKE if self._rng.chance(0.4) else Stance.GUARD)


class AdaptiveAgent(SupportsDecide):
    """Counters the opponent's most frequent stance, with noise.

    The strongest built-in, and still beatable: a player who notices they are
    being read can invert their own pattern and punish it. That is the
    behaviour a good opponent should have -- readable in principle, costly to
    read in practice.

    Noise is not decoration. A purely deterministic counter-picker is solvable
    in three rounds, and an unbeatable-then-trivially-beaten opponent is the
    worst of both.
    """

    name = "adaptive"

    #: How often to ignore the read. Roughly a third keeps the agent
    #: unexploitable enough to stay interesting without feeling arbitrary.
    NOISE = 0.30

    def __init__(self, rng: RNG) -> None:
        self._rng = rng

    def decide(self, view: MatchView) -> Decision:
        # Spend whenever the souls are there. Hoarding them for a better moment
        # measured badly: an early version only spent when behind and lost a
        # 200-match series to RandomAgent, which spends on sight. Souls are
        # already paid for with a weak FOCUS round, so holding them just means
        # taking damage you had the means to avoid.
        spend = view.can_spend_soul

        if not view.opponent_history or self._rng.chance(self.NOISE):
            return Decision(stance=self._rng.choice(tuple(Stance)), spend_soul=spend)

        # Recent rounds carry more signal than the whole match.
        recent = view.opponent_history[-5:]
        most_common = Counter(recent).most_common()
        top = most_common[0][1]
        tied = sorted(
            (stance for stance, count in most_common if count == top),
            key=lambda s: s.value,
        )
        predicted = tied[0] if len(tied) == 1 else self._rng.choice(tuple(tied))
        stance = _COUNTER[predicted]

        # If our element is losing the matchup, damage is a bad plan; bank
        # Soul instead and win with the arena mechanic.
        if beats(view.opponent.element, view.you.element) and stance is Stance.STRIKE:
            stance = Stance.FOCUS

        return Decision(stance=stance, spend_soul=spend)


# Registered rather than listed in a dict, so a third-party package can add an
# agent -- an LLM-backed one, a Lab's house opponent -- by declaring a
# `rivalforge.agents` entry point, with no change to this file.
for _agent in (RandomAgent, AggressiveAgent, DefensiveAgent, AdaptiveAgent):
    AGENTS.register(_agent.name, _agent)


class _AgentNames(Mapping[str, type]):
    """A read-only mapping view over the agent registry.

    Exists so `AGENT_REGISTRY` keeps behaving like the dict it used to be for
    callers that iterate or index it, while the registry stays the single
    source of truth -- including plugins discovered at runtime.
    """

    def __getitem__(self, key: str) -> type:
        return AGENTS.get(key)

    def __iter__(self):
        return iter(AGENTS.names())

    def __len__(self) -> int:
        return len(AGENTS)


AGENT_REGISTRY: Mapping[str, type] = _AgentNames()


def build_agent(name: str, rng: RNG) -> SupportsDecide:
    """Construct an agent by name, built-in or plugged in.

    Raises:
        UnknownPlugin: a KeyError subclass whose message lists what is
            available, so a mistyped agent name is actionable.
    """
    return AGENTS.get(name)(rng)
