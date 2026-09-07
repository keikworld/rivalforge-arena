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

- [x] **Wallet control, not just ownership.** A signature challenge proving the
      player holds the key, not merely that they copied an address. Message
      signatures only -- never a transaction, never key material. 74 security
      tests covering replay, expiry, domain binding, flooding and enumeration.
- [x] **Ownership gating on every use**, failing closed when it cannot be
      confirmed.
- [x] **Audit trail** with deliberate data minimisation, and a secrets scanner
      in CI so nothing sensitive reaches the repository.
- [x] **Pluggable session storage**, file-backed so `connect` and `play` share
      a session across processes.
- [x] `PlayerStore` on Postgres, behind the existing port. Six tables, not 96.
      Sessions and the audit trail moved with it; every store implementation
      is held to the same contract tests.
- [ ] Encryption at rest for wallet linkage; the migration should assume the
      database will one day be dumped.
- [x] **Telegram client**, reusing `cli/render.py` — the renderer was pure
      string functions for exactly this reason, and it paid off. A thin
      `urllib` Bot API client rather than a framework, handlers that return
      actions instead of performing I/O, HMAC-signed callbacks bound to the
      user, a per-user token bucket, and one escaping choke point for
      attacker-written NFT names. Long polling, so there is no inbound
      socket. See [`TELEGRAM.md`](TELEGRAM.md).
- [ ] Quick-time events, which need a timing channel the terminal cannot give.
- [ ] Daily rotating arena, on the injected `Clock`.
- [ ] Ladder and rank progression, already modelled and tested.
- [x] Rate limiting on the chat surface, per user, checked before any work.
- [ ] An audit log of match results.
- [ ] Shared conversation state, so the bot can run more than one worker.

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
