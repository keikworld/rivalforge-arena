#!/usr/bin/env python3
"""Agent-versus-agent balance harness.

Runs every built-in agent against every other, on every arena, and reports win
rates and match lengths. This is how the numbers in `engine/balance.py` were
chosen -- by measurement, not by feel.

It is also how three real bugs were found that no unit test would have caught,
because each was a *balance* failure rather than a wrong answer:

* the defensive agent never attacked, so it had no win condition (9% win rate);
* `veil` negated a whole round, which could not be priced at any soul cost;
* `rewind` restored the BP the fighter already had, so it did nothing.

Usage::

    python tools/balance_sweep.py                # full report
    python tools/balance_sweep.py --matches 400  # tighter confidence
    python tools/balance_sweep.py --arena blazing_rift

Healthy means two things at once, and they pull in different directions:

* *Per arena*, win rates may skew widely (15-80%). Arenas are supposed to
  favour a playstyle -- that is what gives them identity.
* *Aggregated*, every agent must land between 30% and 70%, the adaptive agent
  must be strongest (reading an opponent has to pay), and matches must average
  4-14 rounds -- the band that keeps a duel to about a minute.
"""

from __future__ import annotations

import argparse
import itertools
import sys
from collections import Counter

from rivalforge.agents.builtin import AGENT_REGISTRY, build_agent
from rivalforge.content.loader import load_content
from rivalforge.content.schema import Battlefield, Element, GameContent
from rivalforge.engine.fighter import Fighter
from rivalforge.engine.match import Match, Side, play
from rivalforge.engine.rng import RNG

AGENTS = sorted(AGENT_REGISTRY)

# Per-arena gates are deliberately wide. Arenas are *supposed* to favour a
# playstyle -- Whisperwind has no hazard and an expensive mechanic, so the
# stance read decides it; Tide of Trials heals, so it rewards patience. Forcing
# every arena to 50/50 would make all six feel identical.
#
# The aggregate gates are what must be tight: whatever each arena favours, the
# game as a whole has to be fair, and reading an opponent has to pay.
ARENA_MIN_WIN_RATE = 0.15
ARENA_MAX_WIN_RATE = 0.80
MIN_WIN_RATE = 0.30
MAX_WIN_RATE = 0.70
MIN_ROUNDS = 4.0
MAX_ROUNDS = 14.0


def _reference_fighter(content: GameContent, name: str) -> Fighter:
    """A neutral, average fighter.

    Both sides use the same one so the sweep measures *policy*, not the luck of
    two mint hashes. Fighter variety is measured separately.
    """
    return Fighter(
        mint="So11111111111111111111111111111111111111112",
        name=name,
        supremacy=content.supremacy("keiknight_warrior"),
        element=Element.WIND,
        power=10,
        guard=10,
        focus=10,
    )


def run_arena(
    content: GameContent, arena: Battlefield, matches: int
) -> tuple[dict[str, float], float, Counter]:
    """Round-robin every agent pairing on one arena."""
    wins: dict[str, list[int]] = {a: [0, 0] for a in AGENTS}
    lengths: list[int] = []
    reasons: Counter = Counter()

    for left, right in itertools.permutations(AGENTS, 2):
        for seed in range(matches):
            match = Match.create(
                _reference_fighter(content, "A"),
                _reference_fighter(content, "B"),
                arena,
                content,
                seed=seed,
            )
            outcome = play(
                match,
                {
                    Side.A: build_agent(left, RNG(seed * 2 + 1)),
                    Side.B: build_agent(right, RNG(seed * 2 + 2)),
                },
            )
            wins[left][1] += 1
            wins[right][1] += 1
            if outcome.winner is Side.A:
                wins[left][0] += 1
            elif outcome.winner is Side.B:
                wins[right][0] += 1
            lengths.append(outcome.rounds)
            reasons[outcome.reason] += 1

    rates = {a: won / played for a, (won, played) in wins.items()}
    return rates, sum(lengths) / len(lengths), reasons


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--matches", type=int, default=120,
        help="matches per agent pairing per arena (default: 120)",
    )
    parser.add_argument("--arena", help="limit the sweep to one arena id")
    args = parser.parse_args(argv)

    content = load_content()
    arenas = (
        [content.battlefield(args.arena)] if args.arena else list(content.battlefields)
    )

    header = f"{'arena':<22}{'rounds':>8}  " + "".join(f"{a[:9]:>11}" for a in AGENTS)
    print(header)
    print("-" * len(header))

    healthy = True
    totals: dict[str, list[int]] = {a: [0, 0] for a in AGENTS}
    all_lengths: list[float] = []

    for arena in arenas:
        rates, avg_rounds, reasons = run_arena(content, arena, args.matches)
        ok = MIN_ROUNDS <= avg_rounds <= MAX_ROUNDS and all(
            ARENA_MIN_WIN_RATE < r < ARENA_MAX_WIN_RATE for r in rates.values()
        )
        healthy &= ok
        marker = " " if ok else "!"
        print(
            f"{marker}{arena.id:<21}{avg_rounds:>8.1f}  "
            + "".join(f"{100 * rates[a]:>10.0f}%" for a in AGENTS)
        )
        all_lengths.append(avg_rounds)
        for agent, rate in rates.items():
            totals[agent][0] += round(rate * 1000)
            totals[agent][1] += 1000

    if len(arenas) > 1:
        print("-" * len(header))
        overall = {a: w / p for a, (w, p) in totals.items()}
        mean_rounds = sum(all_lengths) / len(all_lengths)
        print(
            f"{'ALL ARENAS':<22}{mean_rounds:>8.1f}  "
            + "".join(f"{100 * overall[a]:>10.0f}%" for a in AGENTS)
        )
        aggregate_ok = (
            MIN_ROUNDS <= mean_rounds <= MAX_ROUNDS
            and all(MIN_WIN_RATE < r < MAX_WIN_RATE for r in overall.values())
            and max(overall, key=lambda a: overall[a]) == "adaptive"
        )
        healthy &= aggregate_ok
        if not aggregate_ok:
            print("  ^ aggregate gate failed")

    print()
    print(
        f"gates: per-arena win rate in ({ARENA_MIN_WIN_RATE:.0%}, {ARENA_MAX_WIN_RATE:.0%}); "
        f"aggregate in ({MIN_WIN_RATE:.0%}, {MAX_WIN_RATE:.0%}) with adaptive strongest; "
        f"rounds in [{MIN_ROUNDS:.0f}, {MAX_ROUNDS:.0f}]"
    )
    print("HEALTHY" if healthy else "UNHEALTHY -- arenas marked '!' failed a gate")
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
