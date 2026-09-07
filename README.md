# RivalForge

Sixty-second NFT duels. Any NFT, from any collection, is a playable fighter the
moment its owner connects a wallet — no custom metadata, no minting, no
per-collection integration.

```
$ rivalforge play
$ rivalforge watch --a adaptive --b aggressive
$ rivalforge wallet <your-wallet-address> --force
```

This is a ground-up rewrite. The previous codebase is dissected in
[`docs/LESSONS_LEARNED.md`](docs/LESSONS_LEARNED.md); its short version is that
135,000 lines could not be started, and the parts that mattered had been
silently dead for the life of the project.

---

## Quick start

```bash
pip install -e ".[dev]"

rivalforge play                  # play against an agent, no wallet needed
rivalforge fighter <mint>        # what fighter does this NFT make?
rivalforge features              # which features are on
pytest                           # 325 tests
pytest -m integration            # 5 more, against live mainnet
python tools/balance_sweep.py    # the balance harness
```

The engine has **no runtime dependencies**. Every dependency is supply-chain
surface, and a game whose core is pure standard library can be audited in an
afternoon.

## The game

A duel is a best-of-nothing race to knock the other fighter's Battle Points to
zero, and it lasts about ten rounds.

Each round both fighters commit to a stance at the same time:

| Stance | Beats | Loses to | Also |
|---|---|---|---|
| **Strike** | Focus | Guard | highest damage |
| **Guard** | Strike | Focus | best defence |
| **Focus** | Guard | Strike | the only way to gather Soul |

On top of the read sit two three-element cycles — fire ▸ wind ▸ water ▸ fire
and light ▸ shadow ▸ time ▸ light — and six arenas, each with its own element,
hazard and Soul mechanic. Spend Soul to mend, purge, veil, ruin or rewind,
depending on where you are standing.

Nothing here is decorative. Every modifier is covered by a test that asserts it
changes the damage, because in the previous codebase every one of them silently
did not.

## How an NFT becomes a fighter

The mint address is hashed. That hash picks an archetype (weighted so the
strong ones stay rare), an element, and a split of a fixed stat budget.

Every fighter gets the **same** stat total, so a lucky mint gives you an
interesting fighter, never a stronger one. Rarity lives in the archetype, which
is visible, rather than in a hidden stat roll, which would be pay-to-win by
accident.

Same mint, same fighter, on any machine, forever. Anyone can recompute their
own fighter offline and check it matches — that is a feature.

## Architecture

```
src/rivalforge/
  security/     validation and log redaction   -- no dependencies
  content/      schema-checked game data       -- depends on security
  engine/       pure combat, zero I/O          -- depends on content
  agents/       policies that play a side      -- depends on engine
  plugins/      ports, registries, adapters    -- depends on engine
  cli/          the only module that prints    -- depends on everything
```

Dependencies point one way. The previous codebase had twenty mutual package
cycles, which is why nothing in it could be extracted or replaced.

**The engine is pure.** No I/O, no clock, no globals, no `random` module. A
match is fully described by its inputs and a seed, which is what makes replays
exact, tests assertable on real numbers, and AI-vs-AI free rather than a second
code path.

**Everything else is a plugin.** Wallet providers, player stores, notifiers,
payment providers, clocks and agents are all selected by configuration from a
registry. A third-party package adds one by declaring an entry point:

```toml
[project.entry-points."rivalforge.agents"]
my_agent = "my_package:MyAgent"
```

**Every feature has a toggle**, declared in `plugins/toggles.py`. Defaults are
safe: nothing that touches money, a chain or a third party is on until someone
turns it on. Asking for an undeclared toggle raises, so a typo cannot read as a
quietly disabled feature.

## Wallet verification

Verified working against Solana mainnet, **with no API key**:

```bash
$ RIVALFORGE_WALLET_PROVIDER=das rivalforge wallet GUfCR9mK...cGgp --force --limit 3

  provider selected : das
  endpoint          : https://api.mainnet-beta.solana.com
  api key           : none (not required)
  wallet            : GUfC...cGgp

  3 NFT(s):
  SolClique Homes #308   1P8g...v8j1
    -> SolClique Homes #308  KW/shadow  PWR 11  GRD 12  FOC 7
  Squid War NFT #4537    12Pr...jtgt
    -> Squid War NFT #4537  EKM/shadow  PWR 17  GRD 8  FOC 5
  SOLEX Void Band #236   12mA...ppdX
    -> SOLEX Void Band #236  FW/water  PWR 9  GRD 16  FOC 5
```

One indexed `getAssetsByOwner` call per wallet, not one RPC round trip per
token. Every request carries a timeout, retries are bounded and jittered, a
circuit breaker drops a failing provider, and a failover chain falls through to
the next one.

The one rule that makes it safe: **an outage is not a denial.** `OwnershipResult`
has three states, not two —

* `verified=True` — checked, and they hold it;
* `verified=False, checked=True` — checked, and they do not;
* `checked=False` — we could not find out.

Collapsing the last two is how a game bans its players during an RPC outage.

## Configuration

| Variable | Default | What it does |
|---|---|---|
| `RIVALFORGE_FEATURE_<NAME>` | see `features` | turn a feature on or off |
| `RIVALFORGE_FEATURES_FILE` | — | JSON file of toggles |
| `RIVALFORGE_WALLET_PROVIDER` | `null` | `das`, `failover`, `null` |
| `RIVALFORGE_WALLET_FAILOVER` | — | comma-separated chain |
| `RIVALFORGE_RPC_ENDPOINT` | public mainnet | any DAS-capable RPC |
| `RIVALFORGE_RPC_API_KEY` | — | optional, raises rate limits |
| `RIVALFORGE_PLAYER_STORE` | `memory` | where players persist |

Secrets come from the environment only — never a file in the repository, never
a CLI argument (those are visible in `ps`), and never a log line: a redaction
filter is installed before anything can log.

## Documentation

| Document | What is in it |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | layers, ports, how to add a plugin |
| [`docs/GAME_DESIGN.md`](docs/GAME_DESIGN.md) | the rules, and why each number is what it is |
| [`docs/SECURITY.md`](docs/SECURITY.md) | threat model and controls |
| [`docs/LESSONS_LEARNED.md`](docs/LESSONS_LEARNED.md) | what went wrong last time, and the rule each failure produced |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | what ships next, and what has to be true first |

## Status

**Phase 1 is complete and playable.** The duel, six arenas, four agents, the
plugin layer, wallet verification, 325 unit tests, 5 live network tests, and a
measured balance gate in CI.

Phase 2 is persistence and a Telegram client. See the roadmap.
