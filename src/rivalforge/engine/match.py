"""The match state machine.

The engine never calls out. It is driven:

    match = Match.create(a, b, arena, content, seed=123)
    while not match.is_over:
        decisions = {side: agent[side].decide(match.view(side)) for side in match.awaiting}
        events = match.submit(decisions)

A human at a terminal, a scripted agent, an LLM agent and a Telegram handler
are all the same caller. That is why AI-vs-AI works for free rather than
needing a second code path -- and a second code path for bots is exactly how
the previous codebase ended up with a battle engine nobody could test.

Both sides commit simultaneously. `MatchView` is what a decider is allowed to
see, and it deliberately excludes the opponent's pending choice and the RNG
state. An agent that cannot see the future cannot cheat, and neither can a
handler that gets its wiring wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Iterable, Mapping, Sequence

from ..content.schema import Battlefield, GameContent, SoulEffect, Stance
from ..security.validation import ValidationError, validate_choice
from . import balance
from .fighter import Fighter
from .resolve import (
    BURN,
    CombatantState,
    DamageBreakdown,
    apply_status_tick,
    compute_damage,
    inflict,
)
from .rng import RNG

__all__ = [
    "Side",
    "Decision",
    "MatchView",
    "Event",
    "EventKind",
    "Outcome",
    "Match",
]


class Side(str, Enum):
    A = "a"
    B = "b"

    @property
    def other(self) -> "Side":
        return Side.B if self is Side.A else Side.A


@dataclass(frozen=True, slots=True)
class Decision:
    """What a fighter commits to for one round.

    `spend_soul` is resolved before damage, so a soul action can prevent or
    undo what the round is about to do rather than only reacting to it.
    """

    stance: Stance
    spend_soul: bool = False

    @classmethod
    def parse(cls, raw: object, *, field_name: str = "decision") -> "Decision":
        """Build a Decision from untrusted input.

        Accepts a `Decision`, a `Stance`, a stance name, or a mapping. Every
        path validates: a handler cannot pass a string straight through into
        the resolver, which is how the previous codebase ended up comparing a
        variant key against a variant type and silently matching nothing.
        """
        if isinstance(raw, Decision):
            return raw
        if isinstance(raw, Stance):
            return cls(stance=raw)
        if isinstance(raw, str):
            return cls(stance=validate_choice(raw, field=f"{field_name}.stance", allowed=Stance))
        if isinstance(raw, Mapping):
            stance = validate_choice(
                raw.get("stance"), field=f"{field_name}.stance", allowed=Stance
            )
            spend = raw.get("spend_soul", False)
            if not isinstance(spend, bool):
                raise ValidationError(f"{field_name}.spend_soul", "must be a boolean")
            return cls(stance=stance, spend_soul=spend)
        raise ValidationError(field_name, f"cannot read a decision from {type(raw).__name__}")


class EventKind(str, Enum):
    """Everything a round can produce, for rendering and for replay logs."""

    ROUND_START = "round_start"
    STANCE = "stance"
    SOUL_SPENT = "soul_spent"
    SOUL_GAINED = "soul_gained"
    DAMAGE = "damage"
    BLOCKED = "blocked"
    STATUS_INFLICTED = "status_inflicted"
    STATUS_DAMAGE = "status_damage"
    HAZARD = "hazard"
    KO = "ko"
    MATCH_END = "match_end"


@dataclass(frozen=True, slots=True)
class Event:
    """One thing that happened. Renderers read these; the engine never prints."""

    kind: EventKind
    side: Side | None = None
    amount: int = 0
    detail: str = ""

    def __str__(self) -> str:
        who = f"[{self.side.value}] " if self.side else ""
        amount = f" {self.amount}" if self.amount else ""
        detail = f" {self.detail}" if self.detail else ""
        return f"{who}{self.kind.value}{amount}{detail}".strip()


@dataclass(frozen=True, slots=True)
class Outcome:
    """The result of a finished match."""

    winner: Side | None  # None is a draw on the round limit
    rounds: int
    final_bp: Mapping[Side, int]
    reason: str


@dataclass(frozen=True, slots=True)
class MatchView:
    """Exactly what one side may see when deciding.

    Excludes the opponent's pending decision and the RNG. An agent handed a
    view cannot see the future, so a stronger agent has to be a better
    *player* rather than a better cheat.
    """

    side: Side
    round_number: int
    arena: Battlefield
    you: Fighter
    opponent: Fighter
    your_bp: int
    opponent_bp: int
    your_souls: int
    opponent_souls: int
    your_statuses: Mapping[str, int]
    opponent_statuses: Mapping[str, int]
    #: Stances this side's opponent has played, oldest first. The read is the
    #: game, so the history that makes reading possible is public.
    opponent_history: tuple[Stance, ...]

    @property
    def can_spend_soul(self) -> bool:
        return self.your_souls >= self.arena.soul_cost


_ALL_SIDES: Final = (Side.A, Side.B)


class Match:
    """A single duel between two fighters.

    Not a dataclass: it owns mutable progression and an RNG stream, and making
    that explicit is clearer than a frozen shell around mutable fields.
    """

    __slots__ = (
        "_fighters", "_states", "_arena", "_content", "_rng", "_hazard_rng",
        "_round", "_history", "_outcome", "_log", "_round_start_bp",
    )

    def __init__(
        self,
        fighters: Mapping[Side, Fighter],
        arena: Battlefield,
        content: GameContent,
        rng: RNG,
    ) -> None:
        self._fighters = dict(fighters)
        self._arena = arena
        self._content = content
        self._rng = rng
        # A separate stream for hazards, so adding or removing a hazard roll
        # does not shift every damage roll after it. Keeps golden tests stable
        # while the game is still being tuned.
        self._hazard_rng = rng.fork("hazards")
        self._states: dict[Side, CombatantState] = {s: CombatantState.initial() for s in _ALL_SIDES}
        self._round = 0
        # BP at the start of the round now in progress. `CombatantState.
        # previous_bp` trails this by one round, which is what REWIND needs.
        self._round_start_bp: dict[Side, int] = {s: balance.STARTING_BP for s in _ALL_SIDES}
        self._history: dict[Side, list[Stance]] = {s: [] for s in _ALL_SIDES}
        self._outcome: Outcome | None = None
        self._log: list[Event] = []

    # -- construction ----------------------------------------------------

    @classmethod
    def create(
        cls,
        fighter_a: Fighter,
        fighter_b: Fighter,
        arena: Battlefield,
        content: GameContent,
        *,
        seed: int,
    ) -> "Match":
        """Start a match. `seed` fully determines every roll in it."""
        return cls(
            fighters={Side.A: fighter_a, Side.B: fighter_b},
            arena=arena,
            content=content,
            rng=RNG(seed),
        )

    # -- inspection ------------------------------------------------------

    @property
    def is_over(self) -> bool:
        return self._outcome is not None

    @property
    def outcome(self) -> Outcome | None:
        return self._outcome

    @property
    def round_number(self) -> int:
        return self._round

    @property
    def seed(self) -> int:
        return self._rng.seed

    @property
    def log(self) -> tuple[Event, ...]:
        """Every event so far, in order. The replay record."""
        return tuple(self._log)

    @property
    def awaiting(self) -> tuple[Side, ...]:
        """Sides that must submit a decision. Empty once the match is over."""
        return () if self.is_over else _ALL_SIDES

    def fighter(self, side: Side) -> Fighter:
        return self._fighters[side]

    def bp(self, side: Side) -> int:
        return self._states[side].bp

    def souls(self, side: Side) -> int:
        return self._states[side].souls

    def view(self, side: Side) -> MatchView:
        """The information `side` is allowed to decide on."""
        other = side.other
        return MatchView(
            side=side,
            round_number=self._round + 1,
            arena=self._arena,
            you=self._fighters[side],
            opponent=self._fighters[other],
            your_bp=self._states[side].bp,
            opponent_bp=self._states[other].bp,
            your_souls=self._states[side].souls,
            opponent_souls=self._states[other].souls,
            your_statuses=dict(self._states[side].statuses),
            opponent_statuses=dict(self._states[other].statuses),
            opponent_history=tuple(self._history[other]),
        )

    # -- the round -------------------------------------------------------

    def submit(self, decisions: Mapping[Side, object]) -> tuple[Event, ...]:
        """Resolve one round from both sides' simultaneous decisions.

        Args:
            decisions: A decision for each of Side.A and Side.B. Values are
                parsed and validated, so a caller may pass raw input.

        Returns:
            The events this round produced.

        Raises:
            RuntimeError: if the match is already over.
            ValidationError: if a decision is missing or malformed.
        """
        if self.is_over:
            raise RuntimeError("cannot submit a decision to a finished match")

        parsed: dict[Side, Decision] = {}
        for side in _ALL_SIDES:
            if side not in decisions:
                raise ValidationError("decisions", f"missing a decision for side {side.value}")
            parsed[side] = Decision.parse(decisions[side], field_name=f"decisions[{side.value}]")

        self._round += 1
        events: list[Event] = [Event(EventKind.ROUND_START, amount=self._round)]

        for side in _ALL_SIDES:
            # `previous_bp` must trail by a full round, not by zero. Setting it
            # to the current BP here made REWIND restore the value it already
            # had -- a mechanic that cost Soul and did nothing.
            state = self._states[side]
            self._states[side] = state.__class__(
                bp=state.bp,
                souls=state.souls,
                statuses=state.statuses,
                previous_bp=self._round_start_bp[side],
            )
            self._round_start_bp[side] = state.bp
            self._history[side].append(parsed[side].stance)
            events.append(
                Event(EventKind.STANCE, side=side, detail=parsed[side].stance.value)
            )

        damage_taken = self._resolve_soul_actions(parsed, events)
        self._resolve_damage(parsed, damage_taken, events)
        self._resolve_hazards(events)
        self._resolve_status_ticks(events)
        self._award_souls(parsed, events)
        self._check_end(events)

        self._log.extend(events)
        return tuple(events)

    # -- round stages ----------------------------------------------------

    def _resolve_soul_actions(
        self, decisions: Mapping[Side, Decision], events: list[Event]
    ) -> dict[Side, float]:
        """Spend souls. Returns each side's incoming-damage multiplier.

        VEIL used to negate a round outright. That could not be priced: cheap
        enough to reach and it dominated every matchup, expensive enough to
        balance and nobody would ever pay for it. Measurement across soul costs
        1-3 showed the aggressive agent swinging between a 42% and a 1% win
        rate on that one dial alone.

        A large reduction instead of a negation is priceable, because its value
        scales with the hit it absorbs rather than being worth a whole round
        regardless.
        """
        damage_taken: dict[Side, float] = {side: 1.0 for side in _ALL_SIDES}
        arena = self._arena

        for side in _ALL_SIDES:
            decision = decisions[side]
            state = self._states[side]
            if not decision.spend_soul:
                continue
            if state.souls < arena.soul_cost:
                # Not an error: an agent may optimistically request it. The
                # request is simply dropped, and the event says so.
                events.append(
                    Event(EventKind.SOUL_SPENT, side=side, detail="denied: not enough souls")
                )
                continue

            state = state.with_souls(state.souls - arena.soul_cost)
            effect = arena.soul_effect

            if effect is SoulEffect.MEND:
                state = state.with_bp(state.bp + arena.soul_magnitude)
            elif effect is SoulEffect.PURGE:
                # Clear statuses *and* recover a little. Pure cleansing is a
                # dead spend whenever nothing has landed on you, which measured
                # as a 15% win rate for the defensive agent on the purge arena
                # -- a mechanic nobody should ever pay for is not a choice.
                state = state.__class__(
                    bp=state.bp, souls=state.souls, statuses={}, previous_bp=state.previous_bp
                ).with_bp(state.bp + arena.soul_magnitude)
            elif effect is SoulEffect.VEIL:
                damage_taken[side] = max(0.0, 1.0 - arena.soul_magnitude / 100.0)
            elif effect is SoulEffect.RUIN:
                target = side.other
                self._states[target] = self._states[target].with_bp(
                    self._states[target].bp - arena.soul_magnitude
                )
                events.append(
                    Event(EventKind.DAMAGE, side=target, amount=arena.soul_magnitude,
                          detail=arena.soul_name)
                )
            elif effect is SoulEffect.REWIND:
                state = state.with_bp(state.previous_bp)
            else:  # pragma: no cover - unreachable while SoulEffect is exhaustive
                raise ValueError(f"unhandled soul effect: {effect!r}")

            self._states[side] = state
            events.append(Event(EventKind.SOUL_SPENT, side=side, detail=arena.soul_name))

        return damage_taken

    def _resolve_damage(
        self,
        decisions: Mapping[Side, Decision],
        damage_taken: Mapping[Side, float],
        events: list[Event],
    ) -> None:
        """Both sides strike at once, from the state as it was before either
        landed. Sequential resolution would silently advantage whoever the
        loop happened to visit first."""
        breakdowns: dict[Side, DamageBreakdown] = {}
        snapshot = dict(self._states)

        for side in _ALL_SIDES:
            other = side.other
            attacker = self._fighters[side]
            defender = self._fighters[other]
            rank = self._content.rank_for(attacker.points).damage_modifier
            breakdowns[side] = compute_damage(
                attacker_power=attacker.power,
                attacker_element=attacker.element,
                attacker_stance=decisions[side].stance,
                attacker_state=snapshot[side],
                attacker_rank_modifier=rank,
                defender_guard=defender.guard,
                defender_element=defender.element,
                defender_stance=decisions[other].stance,
                arena=self._arena,
                rng=self._rng,
            )

        for side in _ALL_SIDES:
            target = side.other
            reduction = damage_taken[target]
            damage = breakdowns[side].final
            if reduction < 1.0:
                # A veiled hit still lands, just softened. The floor keeps it
                # from rounding to nothing, so the round always reads as a hit.
                softened = max(balance.MIN_DAMAGE, int(round(damage * reduction)))
                events.append(
                    Event(
                        EventKind.BLOCKED, side=target, amount=damage - softened,
                        detail=self._arena.soul_name,
                    )
                )
                damage = softened
            self._states[target] = self._states[target].with_bp(self._states[target].bp - damage)
            events.append(Event(EventKind.DAMAGE, side=target, amount=damage))

    def _resolve_hazards(self, events: list[Event]) -> None:
        """The arena bites anyone not attuned to it."""
        arena = self._arena
        if arena.hazard_effect is None or arena.hazard_chance <= 0.0:
            return
        for side in _ALL_SIDES:
            if self._fighters[side].element is arena.element:
                continue  # attuned fighters are immune to their own arena
            if self._states[side].is_down:
                continue
            if self._hazard_rng.chance(arena.hazard_chance):
                duration = (
                    balance.BURN_DURATION if arena.hazard_effect == BURN
                    else balance.CHILL_DURATION
                )
                self._states[side] = inflict(self._states[side], arena.hazard_effect, duration)
                events.append(
                    Event(EventKind.HAZARD, side=side, detail=arena.hazard_effect)
                )

    def _resolve_status_ticks(self, events: list[Event]) -> None:
        for side in _ALL_SIDES:
            self._states[side], damage = apply_status_tick(self._states[side], self._rng)
            if damage:
                events.append(Event(EventKind.STATUS_DAMAGE, side=side, amount=damage))

    def _award_souls(self, decisions: Mapping[Side, Decision], events: list[Event]) -> None:
        """FOCUS is the only way to build Soul: the stance that gives up damage
        is the one that buys the arena's mechanic."""
        for side in _ALL_SIDES:
            if decisions[side].stance is not Stance.FOCUS:
                continue
            state = self._states[side]
            if state.souls >= balance.MAX_SOULS:
                continue
            self._states[side] = state.with_souls(state.souls + balance.SOUL_GAIN_ON_FOCUS)
            events.append(Event(EventKind.SOUL_GAINED, side=side, amount=1))

    def _check_end(self, events: list[Event]) -> None:
        down = [side for side in _ALL_SIDES if self._states[side].is_down]
        final_bp = {side: self._states[side].bp for side in _ALL_SIDES}

        if len(down) == 2:
            # Simultaneous knockout. Treating this as a flat draw looks fair
            # and is not: in a mirror match both fighters cross zero in the
            # same round almost every time, and measurement showed 99% of
            # mirrors ending as draws even though one side was demonstrably
            # ahead entering that round in 87% of them.
            #
            # So the tiebreak is the BP each side held at the *start* of the
            # round: whoever was winning takes it. That uses information the
            # players can see, and it reads correctly at the table. Only a
            # genuinely level position is a draw.
            lead_a = self._states[Side.A].previous_bp
            lead_b = self._states[Side.B].previous_bp
            if lead_a == lead_b:
                self._outcome = Outcome(None, self._round, final_bp, "double knockout, level")
            else:
                winner = Side.A if lead_a > lead_b else Side.B
                events.append(Event(EventKind.KO, side=winner.other))
                self._outcome = Outcome(
                    winner, self._round, final_bp, "double knockout, decided on the lead"
                )
        elif len(down) == 1:
            loser = down[0]
            winner = loser.other
            events.append(Event(EventKind.KO, side=loser))
            self._outcome = Outcome(winner, self._round, final_bp, "knockout")
        elif self._round >= balance.MAX_ROUNDS:
            a, b = final_bp[Side.A], final_bp[Side.B]
            if a == b:
                self._outcome = Outcome(None, self._round, final_bp, "round limit, level")
            else:
                winner = Side.A if a > b else Side.B
                self._outcome = Outcome(winner, self._round, final_bp, "round limit, on points")

        if self._outcome is not None:
            events.append(
                Event(
                    EventKind.MATCH_END,
                    side=self._outcome.winner,
                    amount=self._outcome.rounds,
                    detail=self._outcome.reason,
                )
            )


def play(
    match: Match,
    deciders: Mapping[Side, "SupportsDecide"],
) -> Outcome:
    """Drive a match to completion with one decider per side.

    The whole AI-vs-AI loop. A human match uses the same function with a
    decider that prompts a terminal.
    """
    while not match.is_over:
        decisions = {side: deciders[side].decide(match.view(side)) for side in match.awaiting}
        match.submit(decisions)
    assert match.outcome is not None
    return match.outcome


class SupportsDecide:
    """Structural type for anything that can play a side.

    Kept as a plain class rather than a Protocol so it can also serve as a base
    for the built-in agents without pulling `typing.Protocol` runtime machinery
    into the hot loop.
    """

    name: str = "decider"

    def decide(self, view: MatchView) -> Decision:  # pragma: no cover - interface
        raise NotImplementedError
