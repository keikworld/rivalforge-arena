# Roadmap

Each phase ships fully working before the next starts, and each has a gate that
is a measured number rather than an opinion.

## Phase 1 — the duel — **complete**

The fight, proven fun in a terminal before anything else was built.

- [x] Pure deterministic engine, zero I/O, seeded and replayable
- [x] Fighters derived from a mint address, any NFT, any collection
- [x] Six arenas, two element triangles, three stances, Soul mechanics
- [x] Four agents, so AI-vs-AI works through the same interface as a human
- [x] Plugin layer: ports, registries, entry-point discovery, feature toggles
- [x] Resilience: timeouts, bounded retries, circuit breaker, failover
- [x] Wallet verification, live against mainnet, no API key required
- [x] Playable CLI
- [x] 325 unit tests, 5 live network tests, a measured balance gate in CI

**Gate met:** the balance harness reports HEALTHY on all six arenas; reading an
opponent wins 67% against 41% for random.

## Phase 2 — a game other people can play

Persistence and Telegram. Nothing here is started.

- [ ] **Wallet control, not just ownership.** A signature challenge proving the
      player holds the key, not merely that they copied an address. This is the
      gap that matters most: today someone can play with any wallet's NFTs.
- [ ] `PlayerStore` on Postgres, behind the existing port. Six tables, not 96.
- [ ] Encryption at rest for wallet linkage; the migration should assume the
      database will one day be dumped.
- [ ] Telegram client, reusing `cli/render.py` — the renderer is already pure
      string functions for exactly this reason.
- [ ] Quick-time events, which need a timing channel the terminal cannot give.
- [ ] Daily rotating arena, on the injected `Clock`.
- [ ] Ladder and rank progression, already modelled and tested.
- [ ] Rate limiting and an audit log of match results.

**Gate:** fifty real players, and a day-2 retention number worth looking at.

## Phase 3 — sticky, and earning

- [ ] **Daily boss** — one global boss, everyone chips, contributors split the
      pot.
- [ ] **Temporal boss** — yesterday's top player becomes today's boss, with
      their NFT and their stats. The best idea carried over from the old
      design, and the reason to open the app tomorrow.
- [ ] Telegram Stars, behind the `payments` toggle.
- [ ] Collection partners: a branded arena and a private leaderboard, with a
      share of what their holders spend.

**Gate:** one collection signed, and one payment from someone you have never
met.

## Phase 4 — only if the numbers hold

- [ ] Sponsorship marketplace — brand-funded prize pools, fighter sponsorship.
      Close three deals by hand over DMs first; if you cannot, software will not.
- [ ] LLM agents. The interface is ready — `decide(view) -> Decision`, with the
      return validated exactly like a player's input — but it needs its own
      phase for latency, cost, and the prompt-injection surface of feeding
      opponent-supplied display names into a model.
- [ ] Scholar/Manager rentals. Deliberately last: it re-introduces the
      extraction dynamic that killed the last cycle. It is a liquidity feature
      for a game people already play, not a reason to play.

## Standing rules

1. No exception handler swallows without re-raising. Let it crash.
2. CI on every commit, and the build fails if any module cannot be imported.
3. No document is written in the past tense until a test passes.
4. One feature fully working, tested and documented before the next starts.
5. Every new service is a plugin behind a port and a toggle, defaulting to off.
