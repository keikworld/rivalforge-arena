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

## Wallet authentication

### Why this cannot drain a wallet

The guarantee, first:

* We request a signature over **human-readable text**, never a transaction. A
  message signature moves nothing: no transfer, no delegation, no token
  approval, no program invocation.
* We never ask for, receive, store, transmit or log a private key or seed
  phrase. No key material enters the process.
* There is **no code path in this repository that can construct a Solana
  transaction**, and a test asserts it by scanning every module for
  transaction-building and key-handling symbols.

One further attack deserves naming, because "we only sign messages" is not by
itself sufficient. A hostile site can ask a wallet to sign bytes that are
secretly a *serialised transaction* -- blind signing. The defence is that our
message is constrained to printable ASCII beginning with an alphanumeric
character, while a Solana transaction begins with a compact-u16 signature
count, a byte in 1..255. The constraint is enforced at construction and
asserted in the tests.

The signed text also says, in plain words, that it is not a transaction. The
player reading their wallet prompt is the last line of defence and deserves a
sentence they can act on.

### The flow

1. `begin(wallet)` mints a single-use, wallet-bound challenge with a 256-bit
   nonce and a five-minute expiry.
2. The player signs it in their own wallet.
3. `complete(nonce, signature)` verifies and issues a session.

Step 3 is where implementations usually go wrong. The message verified is the
one **rebuilt from server-held state**, never one the client supplied -- a
verifier that checks a client-supplied message proves only that the caller can
sign something it chose.

### Controls

| Attack | Control |
|---|---|
| Replay | 256-bit nonce, single use, atomic get-and-delete. A *failed* attempt burns the nonce too, so signatures cannot be ground against a live challenge. |
| Concurrent replay | `consume` is atomic; a test races eight threads and asserts exactly one wins. |
| Phishing replay | The domain is bound into the signed text and re-checked at verification. |
| Stale challenge | Five-minute expiry, checked against an injected clock, with a 30-second skew allowance. |
| Enumeration | Every failure returns one generic message. The specific reason goes to the audit trail and the log only. |
| Challenge flooding | Five live challenges per wallet; a bounded, self-evicting store; malformed addresses rejected before anything is stored. |
| Session theft from storage | Tokens are stored as SHA-256 hashes. A dump of the session store yields no live sessions. |
| Forged signature | Verification is libsodium via PyNaCl. No hand-rolled curve arithmetic. |
| Malformed input | Every field is type- and length-checked before use; a bad signature is a clean rejection, never a crash. |

### Ownership is checked on every use

`fighter_for` re-checks ownership each time, rather than trusting an earlier
result: an NFT can be sold between one match and the next.

Ownership **fails closed** -- if we cannot confirm it, we do not grant it.
That is deliberately the opposite of the rule for *reading* a roster, where an
outage is surfaced as an error rather than as an empty list. Refusing to check
is not permission.

## The audit trail

Two rules pulling against each other:

* record enough to investigate abuse;
* record nothing else.

**Recorded:** wallet address, event kind, outcome, UTC timestamp, short reason.
The wallet is the identity being authenticated, so a trail without it records
nothing useful.

**Deliberately not recorded:** IP addresses, user agents, device or browser
fingerprints, geolocation, email addresses, session tokens or their hashes,
signatures, challenge text. None is needed to answer "did this wallet
authenticate, when, and did it work", and each is a liability with no matching
benefit. Tests assert that secrets and network identifiers never reach a record.

Audit records and application logs are different things: the trail holds full
addresses because that is its job; the log never does, because the redaction
filter truncates every address that reaches it. Logs travel further than
databases do.

A failing audit sink is logged and swallowed. Losing a record is bad; failing a
player's login because the audit backend is down is worse, and would be an
availability hole an attacker could trigger deliberately.

## Secrets never reach the repository

`tools/scan_secrets.py` runs in CI on every push and as a test, so it fails on
a developer's machine before a push rather than after. A secret in a public
repository is compromised the moment it lands, however quickly it is deleted.

It scans for private-key blocks, JWTs, AWS/GitHub/Slack/Stripe/OpenAI key
shapes, generic `secret = "..."` assignments, database URLs with embedded
passwords, and hex seeds. Test fixtures that must contain secret-shaped strings
assemble them at runtime and carry a `NOT-A-REAL-SECRET` comment -- excluding
`tests/` wholesale would have been easier and would also have stopped the
scanner ever protecting those files.

`.gitignore` covers key and session filename patterns as a backstop, and a test
asserts no such file is tracked.

## Not yet addressed

Stated plainly, because a security document that only lists strengths is
marketing.

* **Sessions and challenges are single-machine.** The file-backed session store
  is correct for the CLI; a multi-worker deployment needs a shared backend or
  one worker will not recognise another's session. That fails closed -- a
  rejected login, not an accepted one -- but it is not yet fit for scale.
* **No encryption at rest.** The session file holds token hashes and wallet
  addresses, not secrets, but the Postgres store must encrypt wallet linkage
  and should assume the database will one day be dumped.
* **No rate limiting on the game itself**, only on challenge issuance. Needed
  before a public endpoint.
* **No durable audit sink.** Records are in memory and lost on restart. That is
  stated at start-up rather than left for an operator to discover.
* **No match-result audit.** Required before anything of value rides on an
  outcome; the deterministic seed makes it cheap, since a match is one row.

## Reporting

Security issues: open a private advisory rather than a public issue.
