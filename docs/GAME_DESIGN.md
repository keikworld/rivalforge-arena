# Game design

## The loop

A duel is a race to knock the opponent's 100 Battle Points to zero. It takes
about ten rounds, which is roughly sixty seconds on a phone.

Each round both fighters commit to a stance **simultaneously**. Neither sees the
other's choice. That is the whole game: the read.

## Stances

| Stance | Beats | Loses to | Attack | Defence | Soul |
|---|---|---|---|---|---|
| Strike | Focus | Guard | 1.35 | 0.55 | — |
| Guard | Strike | Focus | 0.55 | 1.30 | — |
| Focus | Guard | Strike | 0.70 | 0.90 | +1 |

Winning the read multiplies your damage by 1.40; losing it by 0.68.

Focus is the only way to gather Soul. That is the central tension: the stance
that buys you the arena's mechanic is also the one that gives up tempo, and it
loses to the Strike that most opponents open with.

## Elements

Two disjoint three-cycles:

```
fire ▸ wind ▸ water ▸ fire          light ▸ shadow ▸ time ▸ light
```

Advantage is ×1.30, disadvantage ×0.80. Cross-triangle matchups are neutral on
purpose — a 6×6 table where every cell means something is unreadable, and a
player has to hold this in their head mid-match.

Every element beats exactly one and loses to exactly one, so no element is a
dead pick.

## Arenas

Each has an element, a hazard that spares fighters attuned to it, and a Soul
mechanic.

| Arena | Element | Hazard | Soul mechanic |
|---|---|---|---|
| Blazing Rift | fire | burn, 20% | Purge — clear statuses, recover 12 |
| Tide of Trials | water | chill, 10% | Mend — recover 14 |
| Whisperwind Arena | wind | none | Veil — absorb 65% of this round |
| Tenebris Abyss | shadow | chill, 14% | Ruin — 18 damage, ignores guard |
| Chronos Cradle | time | chill, 8% | Rewind — restore last round's BP |
| Aurora Sanctum | light | burn, 6% | Mend — recover 18 |

A fighter whose element matches the arena deals ×1.15 (Tenebris ×1.20) and is
immune to its hazard.

**Arenas are meant to skew.** Whisperwind has no hazard and an expensive
mechanic, so the read decides it and aggression is rewarded. Tide of Trials
heals, so patience is. Forcing every arena to 50/50 would make all six feel
identical. The *aggregate* is what has to be fair.

## Status effects

* **Burn** — 4 damage at the end of each round, 3 rounds.
* **Chill** — attacks at ×0.80, 2 rounds.

Two hazards that feel different rather than one effect with two names.
Reapplying refreshes the duration rather than stacking it: stacking lets a run
of hazard rolls lock a fighter out of a match, which is the least fun way to
lose.

## Fighters

A fighter is a pure function of its NFT's mint address. The hash picks:

* an **archetype**, weighted `40:26:16:10:6:2` across the six power tiers, so
  the strong ones stay rare;
* an **element**, uniformly;
* a split of a **fixed budget of 30 points** across Power, Guard and Focus, each
  between 4 and 18, nudged by the archetype's bias.

Every fighter has the same stat total. A lucky mint gives you an *interesting*
fighter, never a stronger one. Rarity lives in the archetype, which is visible,
rather than in a hidden stat roll, which would be pay-to-win by accident.

## Archetypes

Carried from the original design, with the six tiers intact.

| | Tier | Bias | Character |
|---|---|---|---|
| Frostable Warriors | 1 | +Guard | endures; low burst |
| Keiknight Warriors | 2 | balanced | no seam, no specialty |
| Keikdark Lords | 3 | +Power +Focus | soul manipulation; thin guard |
| Elemental Keik Master | 4 | +Power | strongest on home ground |
| Soulfeast Overlord | 5 | +Power −Guard | devastating; punishing to misplay |
| Divine Keiknities | 6 | +Power +Guard | no weak stat |

## The damage pipeline

Nine ordered stages, each a named function so a balance change has one home and
a test can pin it:

1. base attack — stats and stance
2. status — chill weakens the attacker
3. stance matchup — the read
4. element matchup — the triangles
5. attunement — the arena favours its own
6. rank — ladder progression
7. variance — ±10%
8. guard — subtracted, after every multiplier
9. floor — a hit is never zero

Guard is **subtractive**, not another multiplier, so it is strongest against
the many small hits it is meant to blunt and weakest against the big ones it is
meant to lose to.

Variance is deliberately narrow. Wide variance makes a skilful read feel
irrelevant.

## Simultaneous knockout

If both fighters fall in the same round, the one who held more BP at the
*start* of that round wins.

This is not a coin flip and it is not cosmetic. Measurement showed identical
fighters drawing **396 times in 400** — and in 87% of those, one side was
clearly ahead going in. The old "double knockout is a draw" rule was discarding
information the players could see. Only a genuinely level position draws.

## How the numbers were chosen

By measurement. `tools/balance_sweep.py` runs every agent pairing on every arena
and reports win rates and match length.

Healthy means two things at once:

* **per arena**, win rates may range 15–80% — arenas have identity;
* **aggregated**, every agent lands between 30% and 70%, the adaptive agent is
  strongest, and matches average 4–14 rounds.

Current state:

```
arena                   rounds     adaptive  aggressive  defensive   random
blazing_rift               9.2          66%         52%        40%      42%
tide_of_trials            11.8          67%         51%        41%      40%
whisperwind_arena          8.1          73%         61%        21%      45%
tenebris_abyss             8.3          60%         41%        59%      39%
chronos_cradle            10.3          75%         58%        27%      39%
aurora_sanctum            11.1          63%         41%        52%      42%
ALL ARENAS                 9.8          67%         51%        40%      41%
```

Reading an opponent pays — the adaptive agent wins 67% against 41% for random —
without being a lock. A new player is not hopeless; a good one is clearly
better.

## What is deliberately not here yet

* **Quick-time events.** The original design's moment of real dexterity. It
  needs a timing channel the terminal cannot fairly provide, and it is
  meaningless for agents. Phase 2, with the Telegram client.
* **Multi-fighter teams.** One duel has to be good first.
* **Any token or yield.** The lesson of the last cycle is that an economy
  layered on a game nobody would play without it collapses when inflow stops.
