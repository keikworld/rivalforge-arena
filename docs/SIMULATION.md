# The simulation

The test suite answers "does this function do what it says". The simulation
answers a different question:

> What happens when a few hundred people use this at once, a quarter of them
> are hostile, and the chain goes down in the middle of it?

```bash
python tools/simulate.py                          # one run, all phases
python tools/simulate.py --runs 2000              # a campaign
python tools/simulate.py --phase abuse            # one phase
python tools/simulate.py --runs 500 --json out.json --html out.html
```

Exit code is 1 if any invariant was broken, so it works as a gate.

## The sandbox

`tools/sandbox.py` builds the whole game against fakes:

* **Wallets are real ed25519 keypairs.** A fake signature would exercise a fake
  verifier, and the signature path is the one thing here that must not be
  approximated. Keys are generated in memory, used once, thrown away.
* **The chain is a dictionary** that can also hand out NFTs, take them away
  mid-session, go down, and come back — the four things a real indexer does and
  the four the game has to survive.
* **Telegram is a queue.** Updates in, actions out, and every message the bot
  would have sent is kept for inspection.

It lives in `tools/`, not in the package, so **no deployment can import it**.
`FakeWalletProvider` is deliberately unregistered in the plugin registry for
the same reason: a fake that can be selected by a stray environment variable is
a fake that eventually is.

## The phases

| Phase | What it puts pressure on |
|---|---|
| `lifecycle` | the happy path, end to end, for every player |
| `interrupted` | every way a fight can be cut in half |
| `abuse` | forged, stolen, replayed and malformed input |
| `outage` | the chain going down mid-session, and coming back |
| `simultaneous` | every player fighting at once, advanced round by round |
| `concurrency` | many players in flight on real threads |
| `soak` | a long weighted random walk over every command |

### Half-cut fights

Nine of them, because this is where a chat bot rots — each leaves state
somewhere the happy path never does:

forfeit · disconnect mid-fight · session expiry mid-fight · conversation
evicted mid-fight · NFT sold mid-fight · a second `/play` mid-fight · a stance
after the match ended · the bot restarted mid-fight · the player simply stops
replying.

After each one the simulation checks the same thing: **can they start again?**

## The invariants

Checked after every action, not at the end. A violation's cause is the action
immediately before it, and a report that says "somewhere in 40,000 messages" is
one nobody can act on.

* no message exceeds Telegram's limit — an over-long message is silently
  rejected by the API;
* **a session token never reaches a message** — it is a bearer credential;
* **a wallet appears only in its owner's chat** — the address is *not* a secret
  and the challenge has to contain it, because a wallet must show its owner
  which address they are signing for. What would be a leak is that address
  turning up in somebody else's chat;
* every fenced block is balanced, and no attacker-written text escapes it;
* every button fits in 64 bytes and verifies for the chat it was sent to;
* the conversation store stays bounded;
* concurrent matches never swap state — each match's seed and arena are
  fingerprinted before the round-robin and checked after;
* the rendered outcome matches the engine's verdict;
* `handle()` never raises. A bot that dies on one update is a bot anyone can
  stop.

## A campaign varies the shape

A thousand runs of identical parameters is one run measured a thousand times.
Each run in a campaign gets a different number of players, a different NFT
count (including zero), a different opponent agent, a different outage rate,
ownership enforcement on or off, and sometimes a conversation store far too
small — so a bug that needs an unusual combination has a chance to appear.

## In CI

`tests/test_simulation.py` runs a miniature campaign on every commit, plus
tests that the guard itself catches planted violations. A harness that cannot
fail proves nothing.

## Three bugs the harness found in itself

Worth recording, because all three were the same shape and none of them were in
the product:

1. **Two lists, one cursor.** Sends and edits were concatenated and tracked
   with a single index. Every new send shifted the positions, so already-checked
   edits were re-checked against the wrong player and reported as forged
   buttons. Same root cause as the redaction rules that dispatched on their
   index — positional bookkeeping breaks when something is inserted.
2. **"The last message" is not "this player's reply."** With players
   interleaved, the newest entry in a shared log belongs to whoever acted last.
   The connect flow read it and concluded that eleven of twelve players never
   received a challenge.
3. **A shared "last reply" across threads.** The concurrency phase runs real
   threads; one field held the most recent reply for all of them. It reported
   one player's board as another's outcome, and looked exactly like a rendering
   bug in the product.

The lesson each time: state that is correct for one actor is wrong for two.
Which is precisely what the simulation exists to find — it just found it here
first.

## The campaign that has been run

2,000 independent simulations, September 2026. `sim-results/campaign.json` holds
the full record and `sim-results/report.html` the readable version.

| | |
|---|---|
| simulations | 2,000 |
| simulated players | 60,966 |
| updates handled | 6,120,662 |
| messages inspected | 5,068,259 |
| buttons inspected | 15,764,467 |
| fights started | 531,029 |
| fought to a finish | 181,967 |
| cut short deliberately | 53,244 |
| peak simultaneous fights | 70 |
| wall clock | 961s |
| **invariant violations** | **0** |
| **unhandled errors** | **0** |

Fights ran a mean of 11.2 rounds (range 2–30, the 30 being the draw limit).
Simulated players choose stances at random and lost 58.0% against the scripted
agents that read — the same direction and roughly the same margin the balance
harness reports, which is the cross-check that the two harnesses agree.

The chain served 60,794 outages across 222,924 roster reads and 76,715
ownership checks. Every one of them degraded rather than denied: a roster
outage never rendered as "you have no NFTs", and ownership never granted a
fighter it could not confirm.

Rejected, without exception: 14,000 malformed or forged callbacks, 20,000
malformed updates, 6,000 wallet flows attempted in a group chat, 15,289 bad
logins, and 390,000 flood messages.
