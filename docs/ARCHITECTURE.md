# Architecture

## Layers

Dependencies point one way. Nothing to the left may import anything to the
right.

```
security  <-  content  <-  engine  <-  agents
                              ^     <-  plugins
                              |
                             cli  (the only module that performs I/O)
```

| Package | Depends on | Responsibility |
|---|---|---|
| `security/` | nothing | validation, log redaction |
| `content/` | `security` | schema-checked game data |
| `engine/` | `content` | pure combat: no I/O, no clock, no globals |
| `agents/` | `engine`, `plugins` | policies that play a side |
| `plugins/` | `engine` | ports, registries, adapters, toggles, resilience |
| `cli/` | everything | the only code that prints or reads |

CI fails if any module cannot be imported, which is the cheapest possible guard
against the cycle problem that made the previous codebase unextractable.

## The engine is pure

`engine/` performs no I/O, reads no clock, touches no global state, and never
calls the `random` module. Every source of chance is an `RNG` instance threaded
through the call that needs it.

A match is therefore fully described by its inputs plus a seed. That buys four
things at once:

* **Replay.** A disputed result can be re-run exactly — which matters the moment
  money is attached to an outcome.
* **Exact tests.** Combat can be asserted on specific numbers rather than
  ranges, so an unintended balance change fails a test instead of being a
  feeling.
* **No cross-match leakage.** Global RNG state would make one match's outcome
  depend on how many others ran first. That is a real fairness bug once matches
  run concurrently, and it is unfixable by testing.
* **AI for free.** A pure engine that emits events and awaits decisions has no
  idea whether a human or a policy is answering.

## The match loop

The engine is driven, never calling out:

```python
match = Match.create(fighter_a, fighter_b, arena, content, seed=123)
while not match.is_over:
    decisions = {side: agents[side].decide(match.view(side)) for side in match.awaiting}
    events = match.submit(decisions)
```

A terminal prompt, a scripted agent, an LLM and a Telegram handler are all the
same caller. That is why AI-vs-AI needed no second code path — and a second code
path for bots is exactly how the previous codebase ended up with a battle engine
nobody could test.

`MatchView` is what a decider may see. It excludes the opponent's pending
decision and the RNG, so an agent cannot see the future and a mis-wired handler
cannot leak it one.

## Ports and adapters

The core depends only on the protocols in `plugins/ports.py`. Every concrete
service is an adapter, registered and selected by configuration.

**The rule that makes it work: nothing below `plugins/` may import an adapter.**
The core imports the port; the wiring picks the adapter.

| Port | Ships with | Selected by |
|---|---|---|
| `NFTOwnershipProvider` | `null`, `das`, `failover` | `RIVALFORGE_WALLET_PROVIDER` |
| `PlayerStore` | `memory` | `RIVALFORGE_PLAYER_STORE` |
| `Notifier` | `null` | `RIVALFORGE_NOTIFIER` |
| `PaymentProvider` | — | `RIVALFORGE_PAYMENT_PROVIDER` |
| `Clock` | `system`, `fixed` | `RIVALFORGE_CLOCK` |

Every default is inert: no network, no money, no writes. A fresh deployment with
no configuration is safe rather than surprising.

## Adding a plugin

In-process:

```python
from rivalforge.plugins.registries import WALLET_PROVIDERS

@WALLET_PROVIDERS.register("my_indexer")
class MyIndexer:
    name = "my_indexer"

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult: ...
    def list_owned(self, wallet: str, *, limit: int = 100): ...
```

From a separate distribution, with no change to this codebase:

```toml
[project.entry-points."rivalforge.wallet_providers"]
my_indexer = "my_package:MyIndexer"
```

Entry-point groups: `rivalforge.agents`, `rivalforge.wallet_providers`,
`rivalforge.player_stores`, `rivalforge.notifiers`,
`rivalforge.payment_providers`, `rivalforge.clocks`.

A name may be registered only once. Silent override means the plugin that
imports last wins, and which one that is depends on import order.

## Feature toggles

Every optional feature is declared in `plugins/toggles.py` with a default and a
description. Resolution order: explicit override, then
`RIVALFORGE_FEATURE_<NAME>`, then a JSON file at `RIVALFORGE_FEATURES_FILE`,
then the declared default.

Asking for an undeclared toggle raises. A typo that silently reads false is a
feature that is off in production and on in your head.

Toggles resolve once at start-up. Reading the environment on every check would
let a feature flip mid-match.

## Resilience

Every call leaving the process goes through `plugins/resilience.py`:

* **Nothing waits forever.** Every outbound call carries a timeout, and a
  `RetryPolicy` carries a total wall-clock budget across all attempts.
* **Retries are bounded and jittered.** Unbounded retries turn a provider's
  wobble into a self-inflicted denial of service; jitter stops a fleet retrying
  in lockstep.
* **Only transient failures retry.** `TransientError` retries;
  `PermanentError` never does — retrying a malformed address spends latency and
  rate limit to get the same answer.
* **A failing dependency is dropped.** `CircuitBreaker` opens after consecutive
  failures so the game degrades in milliseconds instead of stalling.
* **Failover.** `FailoverWalletProvider` chains providers, falling through only
  on an *unchecked* result.

A permanent failure deliberately does **not** count toward the breaker: one bad
request must not take a healthy provider offline for everyone.

## Testing strategy

| Kind | Where | What it protects |
|---|---|---|
| Unit | `tests/test_*.py` | behaviour of one function |
| Property | Hypothesis, in `test_engine.py` | no mint can make an illegal fighter |
| Golden | `test_engine.py` | the RNG stream is stable across machines |
| Regression | named for audit findings | the specific bugs that killed the last codebase |
| Balance | `TestArenaHealth`, `tools/balance_sweep.py` | the game stays fun |
| Integration | `test_wallet_live.py`, `-m integration` | the network path really works |

Balance tests are the unusual one. A balance regression raises nothing and
returns nothing wrong — the game just stops being fun. Measurement is the only
way to catch it.
