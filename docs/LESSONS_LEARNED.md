# Lessons learned

Every rule in this codebase exists because something specific went wrong in the
one before it. This file keeps the reasoning attached to the rule, so a future
change knows what it is undoing.

The prior audit is the evidence base: 135,304 lines of Python across 409 files,
of which **18 of 266 modules could be imported at all**.

---

## From the previous codebase

### 1. A missing key must be a crash, not a `None`

**What happened.** The combat code read `technique_damage_bonus`; the data file
said `technique_damage_boost`. It read `supremacy_boost.damage_bonus`; the file
nested it at `supremacy_boost.effects.damage_boost`. Every arena *bonus*
resolved to `None` or `0`. The two arena *penalties* happened to match, so the
game punished players and never rewarded them, for its entire life.

**The rule.** Content is parsed into frozen typed objects at load, and a
missing key, an unexpected key, an out-of-range value or a broken
cross-reference is a hard error before the process starts.

**Where it lives.** `content/schema.py`, `content/loader.py`. Rejecting
*unexpected* keys is the half that catches a rename — checking only for missing
keys reports a deleted field when the real bug is a typo.

### 2. One name for one concept, enforced by a type

**What happened.** "Supremacy" was spelled three ways across three data files —
`'Frostable Warriors (FW)'`, `'Keikdark Lords'`, `'Fire'` — with an empty
intersection. The check `if supremacy in battlefield["types"]` could never be
true. Elemental advantage, the core strategic layer, never fired once.

**The rule.** `Element` is an enum. Content naming an element outside it fails
to load. There is exactly one vocabulary.

### 3. Never dispatch on a key as though it were a type

**What happened.** `trigger_qte` set `qte_type` to a variant *key* (`"medium"`)
then matched it against variant *types* (`"press"`). Six of nine variants,
including the default, matched no branch: no prompt was sent, and the timeout
scored a silent failure. The only skill mechanic in the game never appeared.

**The rule.** Player input is parsed into a validated enum at the boundary
(`Decision.parse`) and an unrecognised value raises. There is no path where an
unhandled case is a silent no-op.

### 4. The schema and the query are one artefact

**What happened.** `_get_kpts_modifier` selected a `damage_modifier` column from
the `ranks` table. That table's own `CREATE TABLE`, 3,300 lines away in the same
file, did not define it. The code even said so in a comment: *"Assumes your
'ranks' table will have a damage_modifier column."* It did not. Rank changed a
label and nothing else.

**The rule.** `damage_modifier` is required, range-checked content, and a test
asserts that ranking up actually changes damage.

### 5. Let it crash

**What happened.** 2,717 exception handlers across 4,639 functions. 2,509 never
re-raised; 168 were a bare `pass`. This is *why* lessons 1–4 stayed invisible:
each failed quietly and returned a safe default.

**The rule.** Exceptions propagate. The narrow exceptions are documented at the
point they are made: a renderer must not take a match down, a malformed toggle
file must not stop start-up, one odd asset in a wallet must not hide the other
forty. Each one says why in a comment.

### 6. Layers, or you can never leave

**What happened.** Twenty mutual package dependency cycles. `utils` imported
`services` and `storage`; `storage` imported `ai`; `ai` imported `services`.
Importing a utility pulled in the database, the AI engine and the payment layer.
There was no seam to cut along, which is the decisive reason the rewrite was
cheaper than a refactor.

**The rule.** Dependencies point one way: `security ← content ← engine ←
agents/plugins ← cli`. CI fails if any module cannot be imported.

### 7. Documentation written in the past tense is a lie waiting to be found

**What happened.** `V2_MIGRATION_STEP_BY_STEP.md` marked six phases "✅
COMPLETED", with dates and specifics, describing code whose own tests failed. It
claimed environmental effects referenced real battlefield data; the code
branched on `"volcano"` and `"ice"`, neither of which existed in the game.

**The rule.** No document claims a thing works until a test proves it. This
file, the README and the roadmap all distinguish what is built from what is
planned.

### 8. Never generate a function into the middle of another one

**What happened.** In `damage_pipeline.py`, eight stage functions had been
inserted into the body of `compute_damage`, taking its `return` statement with
them. The public entry point of the combat engine returned `None`. All six of
its own tests failed on it.

**The rule.** CI imports every module and runs every test on every push. This
one is not a design principle, it is a tooling gap — and a tooling gap is what
let it survive.

---

## Learned during this rewrite

### 9. Balance bugs are silent, so they need measurement, not review

Three real bugs surfaced only from running agents against each other in bulk.
None raised, none returned a wrong answer, and no unit test would have found
any of them:

* **The defensive agent never attacked.** It had no win condition and won 9% of
  its matches — 1.7% against the aggressive agent. That is a punching bag, not a
  playstyle, and it made the agent useless as a benchmark.
* **`veil` negated an entire round.** It could not be priced: cheap enough to
  reach and it dominated every matchup; dear enough to balance and nobody would
  ever pay for it. Across soul costs 1–3 the aggressive agent swung between a
  42% and a 1% win rate on that dial alone. It is now a percentage absorption,
  whose value scales with the hit it takes.
* **`rewind` did nothing.** It restored `previous_bp`, which was being set to
  the current BP at the top of the same round. A mechanic that cost Soul and
  returned the value the fighter already had.

**The rule.** `tools/balance_sweep.py` runs every agent pairing on every arena
and gates on measured win rates and match length. A cheap version runs in CI.

### 10. Mirror matches exposed a rule that discarded information

Identical fighters drew **396 times out of 400**, because both crossed zero in
the same round. In 87% of those, one side was measurably ahead entering the
round — the "double knockout is a draw" rule was throwing that away.

Now a simultaneous knockout is decided by who held more BP at the start of the
round. Only a genuinely level position draws.

### 11. Test the premise, not just the assertion

A test asserted that the adaptive agent beats the random agent. It failed, and
it was right to: there is nothing to read in a coin, so counter-picking one is
worth exactly zero. The agent was fine; the test's premise was wrong. It now
asserts adaptive beats a *predictable* opponent, and separately that it is not
*worse* than random.

### 12. Ask the live service before designing around what you assume it needs

The wallet layer was built around a required Helius API key. The first live test
showed the public Solana mainnet RPC serves the DAS read API with no credential
at all — 289 assets returned for a test wallet. The provider was renamed from
`HeliusWalletProvider` to `DasWalletProvider`, the key became optional, and the
default configuration now works out of the box for anyone who clones the repo.

An assumed integration requirement had been about to become a fictional barrier
to entry.

### 13. "Not found" and "not checked" are different answers

The null wallet provider returned an empty list, and the CLI printed "No NFTs
visible for this wallet" — for a provider that had inspected nothing. The same
confusion at the ownership level would deny players during an outage.
`OwnershipResult` carries three states for this reason, and the failover chain
depends on it: only an *unchecked* result falls through to the next provider. If
a definite "no" fell through too, an ownership check could be defeated by making
one provider fail.

### 14. Prefix matching swallowed a valid input

The prompt treated any input starting with `s` as "spend soul", so typing
`strike` silently asked to spend Soul instead of striking. Found by a test that
typed nonsense and then a real word. Matching is now exact.
