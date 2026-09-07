# Running the Telegram bot

Everything a person needs to get the bot up, and everything an operator needs
to know about what it does once it is.

## What players get

```
/start        the welcome, and a Play button
/play         a duel against an agent -- no wallet needed
/connect      link a Solana wallet, read-only
/roster       the NFTs you can fight with
/whoami       which wallet this chat is using
/disconnect   end the session and be forgotten
/help         the list
```

A duel is played with buttons: Strike, Guard, Focus, and a Soul button when
there is enough Soul to spend. The board is edited in place, so a whole match
is one message rather than thirty.

## Getting a token

1. Message [@BotFather](https://t.me/BotFather) on Telegram.
2. `/newbot`, pick a name and a username.
3. Copy the token it gives you. It looks like `123456789:AA...`.

**That token is the bot.** Anyone holding it can read every message sent to
your bot and post as it. Treat it exactly as you would a password:

* it goes in the environment, never in a file in the repository, never in a
  command-line argument — arguments are visible in `ps` and in shell history;
* if it leaks, `/revoke` it in BotFather immediately and set the new one;
* CI fails the build if one is ever committed (`tools/scan_secrets.py`), and
  the logging redaction filter strips it from any line that carries it.

In BotFather, also run `/setprivacy` → **Enable**. Privacy mode means the bot
only receives messages addressed to it, which is less data arriving that we
then have to be careful with.

## Running it

```bash
export RIVALFORGE_FEATURE_TELEGRAM_BOT=1
export RIVALFORGE_TELEGRAM_TOKEN='123456789:AA...'

rivalforge telegram
```

That is a playable bot with no wallet verification: players get a starter
fighter and the game works. Nothing reaches a chain.

To let players fight as NFTs they actually own:

```bash
export RIVALFORGE_FEATURE_WALLET_VERIFICATION=1
export RIVALFORGE_WALLET_PROVIDER=das
# RIVALFORGE_RPC_ENDPOINT and RIVALFORGE_RPC_API_KEY are optional --
# the public mainnet RPC serves DAS with no key.
```

And to keep players, ladders and the audit trail across restarts:

```bash
export RIVALFORGE_FEATURE_PERSISTENCE=1
export RIVALFORGE_DATABASE_URL='postgresql://...'
```

`rivalforge status` prints exactly what a deployment is configured to do.
Run it before and after any change.

### Options

| Flag | Default | What it does |
|---|---|---|
| `--opponent` | `adaptive` | which agent players face |
| `--poll-seconds` | `25` | how long each long poll waits |

There is deliberately no `--token`.

## Deploying

Long polling, not a webhook. The bot makes outbound connections only, so it
needs no public endpoint, no inbound port and no TLS certificate of its own --
which also means there is nothing on the internet to find or scan.

The practical consequences:

* **Run one instance.** Telegram delivers each update once, so two pollers on
  one token split the conversations between them at random. Conversation state
  lives in the process, so half of each player's session would be on the wrong
  worker.
* **A restart ends matches in progress** and players reconnect their wallets.
  That is the accepted cost of not writing bearer tokens and half-finished
  matches to a database.
* **`SIGTERM` is a clean stop.** The loop finishes the update in hand and
  exits, which is what a container restart sends.

On Railway: a worker service, no domain, with the environment variables above.
No exposed port is needed and none should be added.

## What it collects

The numeric Telegram user id, for as long as a conversation is active. Not the
username, not the display name, not the language code, not the chat history.

Wallet connections go into the audit trail (`docs/SECURITY.md`), which records
a wallet, an event, an outcome and a timestamp — and deliberately no IP
address, user agent, device fingerprint or geolocation.

## Operating notes

**Symptom: the bot answers nothing and logs nothing.**
Something else set a webhook on this token. The bot calls `deleteWebhook` at
start-up for exactly this reason; if it still happens, another instance is
running and re-setting it.

**Symptom: it stops with "the bot token is wrong or revoked".**
That is a permanent failure and retrying cannot fix it. The token was revoked
in BotFather, or the wrong one is set.

**Symptom: it logs "poll failed; retrying in Ns" with a growing N.**
Transient network trouble. It backs off to a minute and gives up after twenty
consecutive failures rather than hammering a dead endpoint forever.

**Symptom: a player says a button does nothing and shows "That button is not
for you."**
The callback was signed for a different user, or the bot restarted. Callback
signing keys are per-process by default, so buttons from before a restart stop
working — a mild annoyance, and strictly safer than a hard-coded default key
nobody changes. `/play` gives them fresh buttons.

## Testing it without Telegram

`tests/test_telegram_handlers.py` drives every command and button as plain
dictionaries: no network, no fixtures to record, nothing to wait for. That is
why the hostile cases there are exhaustive rather than representative. One test
in `tests/test_telegram_api.py` runs the real client over a real socket against
a loopback server, so the HTTP path is covered too.
