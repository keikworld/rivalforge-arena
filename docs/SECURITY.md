# Security

## Threat model

What an attacker wants, in the order they will try:

1. **Play with an NFT they do not own** — to use a rare fighter, or to farm a
   ladder with someone else's asset.
2. **Manipulate a match outcome** — predict or influence the RNG, submit an
   illegal move, replay a favourable result.
3. **Extract secrets** — an RPC key, a bot token, a wallet address, from logs,
   errors, process arguments, or a crash dump.
4. **Deny service** — exhaust memory with a hostile content file, hang a worker
   on a slow request, or amplify our retries into someone else's outage.
5. **Impersonate another player** — a display name that renders identically to
   someone else's.

The game holds no private keys and signs nothing. That is the single largest
control: a full compromise of this service cannot move an asset.

## Controls

### Input validation

Everything crossing a trust boundary goes through `security/validation.py`.

* **Validators raise, never coerce.** A validator that returns a safe default
  on bad input means the caller cannot tell "valid zero" from "invalid".
* **Bounds are mandatory.** Every numeric validator takes an explicit range;
  every string one an explicit maximum.
* **Reject structural input, sanitize fuzzy input.** Addresses, identifiers and
  enums are rejected when malformed. Display names are sanitized, because the
  acceptable set is not exact.
* `bool` is rejected where an `int` is wanted — it is an `int` subclass in
  Python, and `True` arriving as `1` has caused real scoring bugs.
* NaN and the infinities are rejected — NaN poisons every comparison it
  touches, and either one in a damage formula ends a match unpredictably.

### Display names

`sanitize_display_name` normalises NFKC, then strips every control, format,
surrogate, private-use and unassigned code point. That is what stops zero-width
joiners and right-to-left overrides being used to render a name identical to
another player's. Length is capped; a name with nothing printable is an error
rather than a silent default.

### Secrets

* Read from the environment only. **Never** a file in the repository, never a
  CLI argument — arguments are visible in `ps` and in shell history.
* `security/redaction.py` installs a logging filter before anything can log.
  It removes secret-shaped `key=value` pairs (including `Authorization: Bearer
  <token>`, which an earlier version of the pattern left exposed), JWTs and PEM
  private-key blocks.
* Wallet addresses are **truncated, not removed**: `So11...1112`. They are
  public on-chain, but a log full of them is a map of who plays what, and logs
  travel further than databases do. Truncation keeps lines correlatable without
  making the log enumerable.
* The filter is a backstop, not a licence. Code should still never pass a
  secret to a log call.

### Content loading

A content file is parsed input, and a Lab will eventually supply its own.

* JSON only — never `pickle`, never `yaml.load`, never `eval`. Each of those
  executes code from a data file.
* A byte-size cap is checked **before** parsing, so a large or deeply nested
  file cannot exhaust memory.
* Parsed into frozen typed objects that reject unknown keys and out-of-range
  values, then cross-checked as a set.

### Network calls

* Every request carries a timeout; every retry policy a total budget.
* Addresses are validated **before** a request is built, so a malformed value
  cannot be smuggled into a URL.
* Providers are read-only by contract. A compromised provider can lie about
  ownership; it can never take anything.
* Error messages are constructed, never echoed from a provider body — a
  provider's error text can contain the request, including a key.
* A test asserts the API key never appears in a returned error.

### Ownership verification

`OwnershipResult` has three states, and the distinction is a security control,
not a nicety:

| State | Meaning |
|---|---|
| `verified=True` | checked, they hold it |
| `verified=False, checked=True` | checked, they do not |
| `checked=False` | we could not find out |

Collapsing the last two would deny every player during an RPC outage. In the
failover chain the same distinction is what stops an attacker defeating an
ownership check by making one provider fail: only an *unchecked* result falls
through to the next provider — a definite "no" ends the chain.

Structural validation of a mint says nothing about ownership. `derive_fighter`
makes no ownership claim; verification is a separate, explicit call.

### Randomness

* Match seeds come from `secrets.randbits`. A predictable seed would let anyone
  who learned it know every roll in advance.
* The stream itself is SPLITMIX64 — deterministic and identical across
  platforms, which is what makes replay meaningful. It is not for cryptographic
  use, and only the seed needs to be unguessable.
* `rng.below` is rejection-sampled, not taken modulo. Modulo skews toward low
  values whenever the bound does not divide 2^64 — a small bias, and exactly
  the kind that becomes "this arena's hazard fires more often than the number
  says".

### Denial of service

* Content files are size-capped before parsing.
* Wallet listing is bounded by both a result limit and a page limit, so a
  wallet with a million assets cannot keep a worker, and a player, waiting.
* `MAX_ROUNDS` stops a pathological pair of defensive policies looping forever.
* The circuit breaker stops us amplifying a provider's outage.

## Not yet addressed

Stated plainly, because a security document that only lists strengths is
marketing.

* **No authentication.** There are no accounts yet. Wallet *ownership* is
  verified; wallet *control* (a signature challenge proving the player holds the
  key) is Phase 2 and is what stops someone playing with an address they merely
  copied.
* **No rate limiting** on the game itself. Needed before a public endpoint.
* **No persistence**, so no encryption at rest yet. When the player store
  lands, wallet linkage is the field that needs encrypting, and the migration
  must assume the database will be dumped.
* **No audit log** of match results. Required before anything of value rides on
  an outcome; the deterministic seed makes it cheap, since a match is one row.

## Reporting

Security issues: open a private advisory rather than a public issue.
