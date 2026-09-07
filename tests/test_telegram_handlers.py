"""Tests for every command and button the bot understands.

`handle()` takes a dictionary and returns a list of actions, so an attack is a
dictionary and an assertion. There is no network here, no fixtures to record,
and nothing to wait for -- which is why the hostile cases can be exhaustive
rather than representative.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rivalforge.auth.audit import AuditTrail, InMemoryAuditSink
from rivalforge.auth.challenge import ChallengeService
from rivalforge.auth.service import WalletService
from rivalforge.auth.session import SessionService
from rivalforge.auth.session_store import InMemorySessionStore
from rivalforge.auth.store import InMemoryChallengeStore
from rivalforge.cli.wiring import Application
from rivalforge.content.loader import load_content
from rivalforge.engine.match import Side
from rivalforge.plugins.adapters import FakeWalletProvider, FixedClock
from rivalforge.plugins.ports import OwnedNFT
from rivalforge.plugins.toggles import Toggles
from rivalforge.security.validation import b58encode
from rivalforge.telegram import handlers, render
from rivalforge.telegram.handlers import (
    AnswerCallback,
    BotHandlers,
    EditMessage,
    SendMessage,
)
from rivalforge.telegram.security import CallbackSigner, RateLimiter
from rivalforge.telegram.state import StateStore

nacl_signing = pytest.importorskip("nacl.signing")

DOMAIN = "rivalforge.game"
URI = "https://rivalforge.game"
KEY = b"k" * 32
USER = 4242
CHAT = 4242

# A mint whose name is the reason `security.py` exists. Minting a token called
# this costs a few cents.
HOSTILE_NAME = "[Claim your airdrop](https://evil.example) `*_"


class Wallet:
    def __init__(self, seed: bytes = b"\x07" * 32) -> None:
        self.key = nacl_signing.SigningKey(seed)
        self.address = b58encode(bytes(self.key.verify_key))

    def sign(self, message: str) -> str:
        return b58encode(self.key.sign(message.encode("utf-8")).signature)


@pytest.fixture(scope="module")
def content():
    return load_content()


@pytest.fixture
def wallet():
    return Wallet()


@pytest.fixture
def provider():
    return FakeWalletProvider()


@pytest.fixture
def app(content, provider):
    clock = FixedClock(datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc))
    challenges = ChallengeService(InMemoryChallengeStore(), clock, domain=DOMAIN, uri=URI)
    sessions = SessionService(clock, store=InMemorySessionStore())
    sink = InMemoryAuditSink()
    return Application(
        content=content,
        features=Toggles(overrides={"telegram_bot": True, "wallet_verification": True}, env={}),
        wallets=WalletService(
            challenges, sessions, provider, AuditTrail(sink, clock), content,
            require_ownership=True,
        ),
        audit_sink=sink,
        clock=clock,
    )


@pytest.fixture
def signer():
    return CallbackSigner(KEY)


@pytest.fixture
def bot(app, signer):
    return BotHandlers(
        app,
        signer=signer,
        limiter=RateLimiter(capacity=1000, refill_per_second=1000.0),
        states=StateStore(),
    )


# -- update builders -------------------------------------------------------


def message(text: str, *, user: int = USER, chat: int = CHAT, kind: str = "private", bot_sender=False):
    return {
        "update_id": 1,
        "message": {
            "message_id": 10,
            "from": {"id": user, "is_bot": bot_sender},
            "chat": {"id": chat, "type": kind},
            "text": text,
        },
    }


def press(data: str, *, user: int = USER, chat: int = CHAT, message_id: int = 10):
    return {
        "update_id": 2,
        "callback_query": {
            "id": "cb-1",
            "from": {"id": user, "is_bot": False},
            "message": {"message_id": message_id, "chat": {"id": chat, "type": "private"}},
            "data": data,
        },
    }


def texts(actions) -> str:
    return "\n".join(getattr(a, "text", "") for a in actions)


def challenge_message(actions) -> str:
    """Pull the text to sign out of the bot's own reply.

    Deliberately read from the chat rather than from the challenge store: this
    is the string a player actually copies into their wallet, so if escaping
    ever mangled it, these tests would be the ones to notice.
    """
    body = texts(actions)
    _, _, rest = body.partition("----- message to sign -----\n")
    signable, _, _ = rest.partition("\n---------------------------")
    assert signable, "the bot did not send anything to sign"
    return signable


def connect(bot, app, wallet, provider, *, nfts=()):
    """Drive a full connect flow and return the actions from the last step."""
    for nft in nfts:
        provider.give(wallet.address, nft)
    issued = bot.handle(message(f"/connect {wallet.address}"))
    signature = wallet.sign(challenge_message(issued))
    return bot.handle(message(f"/signed {signature}"))


# ==========================================================================
# The gate every update passes through
# ==========================================================================


class TestTheGate:
    def test_a_non_mapping_update_produces_nothing(self, bot):
        for bad in (None, [], "update", 5):
            assert bot.handle(bad) == []

    def test_an_empty_update_produces_nothing(self, bot):
        assert bot.handle({"update_id": 1}) == []

    def test_another_bot_is_ignored(self, bot):
        """Two bots replying to each other is a loop nobody is watching."""
        assert bot.handle(message("/play", bot_sender=True)) == []

    def test_an_update_with_no_sender_is_ignored(self, bot):
        assert bot.handle({"message": {"chat": {"id": 1, "type": "private"}, "text": "/play"}}) == []

    def test_a_malformed_user_id_is_ignored(self, bot):
        for bad in ("nine", None, -1, 0, 1.5):
            assert bot.handle(message("/play", user=bad)) == []

    def test_a_flood_is_dropped_in_silence(self, app, signer):
        """Answering a flood is amplifying it."""
        bot = BotHandlers(app, signer=signer, limiter=RateLimiter(capacity=2, refill_per_second=0.001))
        assert bot.handle(message("/help"))
        assert bot.handle(message("/help"))
        assert bot.handle(message("/help")) == []

    def test_a_handler_that_raises_produces_no_actions_and_no_details(self, bot, monkeypatch):
        """A bot that dies on one update is a bot anyone can stop.

        And what it answers with is nothing: an internal error message is a
        map of the internals.
        """
        def boom(self, *args):
            raise RuntimeError("internal detail nobody should see")

        monkeypatch.setitem(handlers._COMMANDS, "/help", boom)
        assert bot.handle(message("/help")) == []

    def test_non_text_messages_get_a_pointer_rather_than_a_crash(self, bot):
        update = message("x")
        del update["message"]["text"]
        actions = bot.handle(update)
        assert "help" in texts(actions).lower()

    def test_an_absurdly_long_message_is_refused_before_parsing(self, bot):
        actions = bot.handle(message("/play " + "x" * 100_000))
        assert "too long" in texts(actions)

    def test_an_unknown_command_offers_the_menu_rather_than_silence(self, bot):
        actions = bot.handle(message("/nonsense"))
        assert isinstance(actions[0], SendMessage)
        assert actions[0].keyboard

    def test_a_command_addressed_to_the_bot_by_name_still_works(self, bot):
        """In a group, Telegram sends `/play@RivalForgeBot`."""
        assert bot.handle(message("/help@RivalForgeBot"))


# ==========================================================================
# Callbacks
# ==========================================================================


class TestCallbacks:
    def test_a_valid_button_is_accepted(self, bot, signer):
        bot.handle(message("/play"))
        actions = bot.handle(press(signer.sign(render.ACTION_STANCE, "strike", USER)))
        assert any(isinstance(a, EditMessage) for a in actions)

    def test_a_button_from_another_users_chat_does_nothing(self, bot, signer):
        """The binding is the control: the payload is signed over the user id."""
        bot.handle(message("/play"))
        stolen = signer.sign(render.ACTION_STANCE, "strike", 999_999)
        actions = bot.handle(press(stolen, user=USER))
        assert actions == [AnswerCallback("cb-1", "That button is not for you.", alert=True)]

    def test_a_forged_payload_does_nothing(self, bot):
        actions = bot.handle(press("st|strike|AAAAAAAAAAAAAAAA"))
        assert all(isinstance(a, AnswerCallback) for a in actions)
        assert "not for you" in texts(actions)

    def test_an_unsigned_payload_does_nothing(self, bot):
        assert "not for you" in texts(bot.handle(press("st|strike")))

    def test_a_press_is_always_acknowledged(self, bot, signer):
        """Telegram spins the button forever otherwise, which reads as broken."""
        for data in ("garbage", signer.sign(render.ACTION_PLAY, "start", USER)):
            actions = bot.handle(press(data))
            assert any(isinstance(a, AnswerCallback) for a in actions)

    def test_a_callback_with_no_message_is_answered_not_ignored(self, bot, signer):
        update = press(signer.sign(render.ACTION_PLAY, "start", USER))
        del update["callback_query"]["message"]
        assert isinstance(bot.handle(update)[0], AnswerCallback)

    def test_an_unknown_action_is_answered(self, bot, signer):
        actions = bot.handle(press(signer.sign("zz", "x", USER)))
        assert "does nothing" in texts(actions)

    def test_a_callback_flood_is_answered_but_not_acted_on(self, app, signer):
        bot = BotHandlers(app, signer=signer, limiter=RateLimiter(capacity=1, refill_per_second=0.001))
        data = signer.sign(render.ACTION_PLAY, "start", USER)
        bot.handle(press(data))
        actions = bot.handle(press(data))
        assert actions == [AnswerCallback("cb-1", "Slow down for a moment.")]


# ==========================================================================
# Playing
# ==========================================================================


class TestPlaying:
    def test_play_draws_a_board_with_stance_buttons(self, bot):
        actions = bot.handle(message("/play"))
        assert len(actions) == 1
        assert isinstance(actions[0], SendMessage)
        labels = [b["text"] for row in actions[0].keyboard for b in row]
        assert {"Strike", "Guard", "Focus"} <= set(labels)

    def test_a_stance_advances_the_match_in_place(self, bot, signer):
        bot.handle(message("/play"))
        actions = bot.handle(press(signer.sign(render.ACTION_STANCE, "guard", USER)))
        edit = next(a for a in actions if isinstance(a, EditMessage))
        assert edit.message_id == 10
        assert "round" in edit.text

    def test_a_match_can_be_played_to_a_finish(self, bot, signer):
        bot.handle(message("/play"))
        for _ in range(60):
            actions = bot.handle(press(signer.sign(render.ACTION_STANCE, "strike", USER)))
            edit = next((a for a in actions if isinstance(a, EditMessage)), None)
            if edit is None:
                break
            if "wins" in edit.text or "DRAW" in edit.text:
                break
        else:  # pragma: no cover
            pytest.fail("the match never ended")
        # The finished match leaves the menu, not stance buttons.
        labels = [b["text"] for row in (edit.keyboard or []) for b in row]
        assert "Strike" not in labels

    def test_a_stance_after_the_match_ends_is_refused_politely(self, bot, signer):
        bot.handle(message("/play"))
        state = bot._states.get(USER)
        state.end_match()
        actions = bot.handle(press(signer.sign(render.ACTION_STANCE, "strike", USER)))
        assert "over" in texts(actions)

    def test_an_unknown_stance_is_refused(self, bot, signer):
        bot.handle(message("/play"))
        actions = bot.handle(press(signer.sign(render.ACTION_STANCE, "flee", USER)))
        assert "Unknown move" in texts(actions)

    def test_forfeiting_ends_the_match(self, bot, signer):
        bot.handle(message("/play"))
        actions = bot.handle(press(signer.sign(render.ACTION_QUIT, "match", USER)))
        assert "forfeited" in texts(actions).lower()
        assert bot._states.get(USER).match is None

    def test_soul_cannot_be_armed_before_it_is_earned(self, bot, signer):
        bot.handle(message("/play"))
        actions = bot.handle(press(signer.sign(render.ACTION_SOUL, "toggle", USER)))
        assert "Not enough soul" in texts(actions)
        assert bot._states.get(USER).soul_armed is False

    def test_soul_arms_and_is_spent_by_the_next_stance(self, bot, signer):
        bot.handle(message("/play"))
        state = bot._states.get(USER)
        # Focus is the only way to gather soul, so take rounds of it until
        # there is enough to spend.
        for _ in range(8):
            if state.match is None:  # pragma: no cover - the match ended first
                pytest.skip("the match finished before soul was available")
            if state.match.view(Side.A).can_spend_soul:
                break
            bot.handle(press(signer.sign(render.ACTION_STANCE, "focus", USER)))
        else:  # pragma: no cover
            pytest.skip("no soul gathered in eight rounds")

        bot.handle(press(signer.sign(render.ACTION_SOUL, "toggle", USER)))
        assert state.soul_armed is True
        bot.handle(press(signer.sign(render.ACTION_STANCE, "strike", USER)))
        assert state.soul_armed is False, "an armed soul must not carry to the next round"

    def test_two_players_have_separate_matches(self, bot, signer):
        bot.handle(message("/play", user=1, chat=1))
        bot.handle(message("/play", user=2, chat=2))
        assert bot._states.get(1).match is not bot._states.get(2).match


# ==========================================================================
# Connecting a wallet
# ==========================================================================


class TestConnecting:
    def test_connect_without_an_address_explains_itself(self, bot):
        actions = bot.handle(message("/connect"))
        assert "/connect" in texts(actions)

    def test_a_malformed_address_is_refused(self, bot):
        actions = bot.handle(message("/connect not-an-address"))
        assert "not a Solana address" in texts(actions)

    def test_the_challenge_is_a_message_and_says_so(self, bot, wallet):
        """The single most important sentence the bot ever sends."""
        actions = bot.handle(message(f"/connect {wallet.address}"))
        body = texts(actions)
        assert "not a transaction" in body
        assert "cannot move anything" in body

    def test_connecting_is_refused_in_a_group(self, bot, wallet):
        """A challenge posted in a group is a challenge every member reads."""
        actions = bot.handle(message(f"/connect {wallet.address}", kind="supergroup"))
        assert "direct message" in texts(actions)
        assert bot._states.get(USER).pending_nonce is None

    def test_the_roster_is_refused_in_a_group(self, bot):
        actions = bot.handle(message("/roster", kind="group"))
        assert "direct message" in texts(actions)

    def test_a_signature_without_a_challenge_is_refused(self, bot):
        actions = bot.handle(message("/signed abcdef"))
        assert "/connect first" in texts(actions)

    def test_a_full_connect_flow_succeeds(self, bot, app, wallet, provider):
        actions = connect(bot, app, wallet, provider)
        assert "Connected" in texts(actions)
        assert bot._states.get(USER).wallet == wallet.address

    def test_a_wrong_signature_is_refused_and_burns_the_challenge(self, bot, app, wallet):
        """A challenge that survives a failed attempt is one you can keep guessing at."""
        issued = bot.handle(message(f"/connect {wallet.address}"))
        signable = challenge_message(issued)
        other = Wallet(seed=b"\x09" * 32)
        actions = bot.handle(message(f"/signed {other.sign(signable)}"))
        assert "did not check out" in texts(actions)
        assert bot._states.get(USER).pending_nonce is None
        # And the same challenge cannot be answered afterwards, even correctly.
        retry = bot.handle(message(f"/signed {wallet.sign(signable)}"))
        assert "/connect first" in texts(retry)

    def test_a_second_connect_replaces_the_first_challenge(self, bot, app, wallet):
        bot.handle(message(f"/connect {wallet.address}"))
        first = bot._states.get(USER).pending_nonce
        bot.handle(message(f"/connect {wallet.address}"))
        assert bot._states.get(USER).pending_nonce != first

    def test_the_full_wallet_address_is_never_echoed_back(self, bot, app, wallet, provider):
        actions = connect(bot, app, wallet, provider)
        assert wallet.address not in texts(actions)

    def test_disconnect_forgets_everything(self, bot, app, wallet, provider):
        connect(bot, app, wallet, provider)
        bot.handle(message("/disconnect"))
        state = bot._states.get(USER)
        assert state.session_token is None
        assert state.wallet is None

    def test_whoami_needs_a_session(self, bot):
        assert "No wallet connected" in texts(bot.handle(message("/whoami")))


# ==========================================================================
# NFT metadata is attacker-controlled text
# ==========================================================================


class TestHostileMetadata:
    def test_a_phishing_name_is_never_rendered_as_a_link(self, bot, app, wallet, provider):
        """The threat this whole surface was designed around."""
        mint = b58encode(b"\x11" * 32)
        connect(
            bot, app, wallet, provider,
            nfts=[OwnedNFT(mint=mint, name=HOSTILE_NAME, collection=None)],
        )
        body = texts(bot.handle(message("/roster")))
        assert "](https://evil.example)" not in body
        # It is inside a fenced block, where the only syntax is a backtick.
        assert body.startswith("```")
        assert "`*_" not in body  # the backtick is escaped

    def test_a_name_full_of_control_characters_does_not_break_the_layout(
        self, bot, app, wallet, provider
    ):
        mint = b58encode(b"\x12" * 32)
        connect(
            bot, app, wallet, provider,
            nfts=[OwnedNFT(mint=mint, name="a‮b‌c\nd", collection=None)],
        )
        body = texts(bot.handle(message("/roster")))
        assert "‮" not in body and "‌" not in body

    def test_an_enormous_name_cannot_push_the_message_off_the_screen(
        self, bot, app, wallet, provider
    ):
        mint = b58encode(b"\x13" * 32)
        connect(bot, app, wallet, provider,
                nfts=[OwnedNFT(mint=mint, name="Z" * 5000, collection=None)])
        body = texts(bot.handle(message("/roster")))
        assert len(body) < 2000

    def test_an_unusable_asset_does_not_cost_the_player_the_others(
        self, bot, app, wallet, provider
    ):
        good = b58encode(b"\x14" * 32)
        connect(
            bot, app, wallet, provider,
            nfts=[
                OwnedNFT(mint="not a mint", name="broken", collection=None),
                OwnedNFT(mint=good, name="fine", collection=None),
            ],
        )
        body = texts(bot.handle(message("/roster")))
        assert "fine" in body

    def test_a_name_that_is_only_invisible_characters_renders_as_unnamed(
        self, bot, app, wallet, provider
    ):
        mint = b58encode(b"\x15" * 32)
        connect(bot, app, wallet, provider,
                nfts=[OwnedNFT(mint=mint, name="​​", collection=None)])
        assert "unnamed" in texts(bot.handle(message("/roster")))


# ==========================================================================
# Ownership
# ==========================================================================


class TestOwnership:
    def test_picking_an_owned_nft_makes_it_your_fighter(self, bot, app, wallet, provider, signer):
        mint = b58encode(b"\x21" * 32)
        connect(bot, app, wallet, provider,
                nfts=[OwnedNFT(mint=mint, name="Pilot", collection=None)])
        bot.handle(message("/roster"))
        actions = bot.handle(press(signer.sign(render.ACTION_PICK, "1", USER)))
        assert bot._states.get(USER).chosen_mint == mint
        assert "Pilot" in texts(actions)

    def test_a_pick_outside_the_roster_is_refused(self, bot, app, wallet, provider, signer):
        mint = b58encode(b"\x22" * 32)
        connect(bot, app, wallet, provider,
                nfts=[OwnedNFT(mint=mint, name="Pilot", collection=None)])
        bot.handle(message("/roster"))
        for argument in ("0", "2", "-1", "99", "nine"):
            actions = bot.handle(press(signer.sign(render.ACTION_PICK, argument, USER)))
            assert "no longer available" in texts(actions)

    def test_ownership_is_rechecked_on_every_match_not_cached(
        self, bot, app, wallet, provider, signer
    ):
        """An NFT can be sold between one match and the next."""
        mint = b58encode(b"\x23" * 32)
        connect(bot, app, wallet, provider,
                nfts=[OwnedNFT(mint=mint, name="Pilot", collection=None)])
        bot.handle(message("/roster"))
        bot.handle(press(signer.sign(render.ACTION_PICK, "1", USER)))

        # They sell it.
        provider._holdings[wallet.address] = []
        actions = bot.handle(message("/play"))
        assert "Pilot" not in texts(actions)
        assert bot._states.get(USER).chosen_mint is None

    def test_a_roster_outage_is_not_reported_as_an_empty_wallet(
        self, bot, app, wallet, provider, monkeypatch
    ):
        """Telling a player their NFTs are gone is the worst way to be wrong."""
        connect(bot, app, wallet, provider)

        def unavailable(*a, **k):
            raise RuntimeError("rpc is down")

        monkeypatch.setattr(app.wallets, "roster", unavailable)
        body = texts(bot.handle(message("/roster")))
        assert "could not read" in body
        assert "no NFTs" not in body

    def test_an_expired_session_is_cleared_rather_than_retried_forever(
        self, bot, app, wallet, provider
    ):
        connect(bot, app, wallet, provider)
        app.wallets.disconnect(bot._states.get(USER).session_token)
        body = texts(bot.handle(message("/roster")))
        assert "expired" in body
        assert bot._states.get(USER).session_token is None

    def test_roster_needs_a_wallet(self, bot):
        assert "Connect a wallet first" in texts(bot.handle(message("/roster")))


# ==========================================================================
# What the bot keeps
# ==========================================================================


class TestDataMinimisation:
    def test_only_the_numeric_user_id_is_kept(self, bot):
        """A username is a real identity in a way a wallet address is not."""
        update = message("/play")
        update["message"]["from"].update(
            {"username": "someone", "first_name": "Real", "language_code": "en"}
        )
        bot.handle(update)
        state = bot._states.get(USER)
        stored = {k: v for k, v in vars(state).items()}
        assert "someone" not in repr(stored)
        assert "Real" not in repr(stored)

    def test_the_conversation_store_is_bounded(self, app, signer):
        bot = BotHandlers(
            app, signer=signer,
            limiter=RateLimiter(capacity=10_000, refill_per_second=10_000.0),
            states=StateStore(max_users=25),
        )
        for user in range(1, 400):
            bot.handle(message("/help", user=user, chat=user))
        assert len(bot._states) <= 25


# ==========================================================================
# End to end: the loop, the handlers and the wallet service as one thing
# ==========================================================================


class LoopbackAPI:
    """A Bot API that hands every reply straight back as the next update.

    Enough to drive a whole session through `Bot` without a socket: the loop
    polls, the handlers answer, and the buttons that come back are the ones a
    player would actually tap.
    """

    def __init__(self, *batches):
        self.batches = list(batches)
        self.sent = []
        self.edited = []
        self.answered = []

    def get_me(self):
        return {"username": "TestBot"}

    def delete_webhook(self):
        pass

    def get_updates(self, offset=None, *, poll_seconds=None):
        return self.batches.pop(0) if self.batches else []

    def send_message(self, chat_id, text, *, keyboard=None):
        self.sent.append((text, keyboard))
        return {"message_id": len(self.sent)}

    def edit_message_text(self, chat_id, message_id, text, *, keyboard=None):
        self.edited.append((text, keyboard))

    def answer_callback_query(self, callback_id, *, text="", alert=False):
        self.answered.append(text)


class TestEndToEnd:
    """The pieces wired together, as they are in `cmd_telegram`."""

    def test_a_whole_session_runs_through_the_loop(self, bot, signer):
        from rivalforge.telegram.bot import Bot

        api = LoopbackAPI(
            [message("/start")],
            [message("/play")],
            [press(signer.sign(render.ACTION_STANCE, "strike", USER))],
        )
        loop = Bot(api, bot, sleep=lambda _s: None)
        assert loop.start()["username"] == "TestBot"
        for _ in range(3):
            loop.poll_once()

        assert len(api.sent) == 2  # the welcome and the opening board
        assert api.edited, "the stance should have edited the board in place"
        assert api.answered == [""]

    def test_every_button_the_bot_offers_verifies_when_pressed_back(self, bot, signer):
        """A button that does not survive its own round trip is a dead button."""
        from rivalforge.telegram.bot import Bot

        api = LoopbackAPI([message("/play")])
        Bot(api, bot, sleep=lambda _s: None).poll_once()
        _, keyboard = api.sent[-1]
        for row in keyboard:
            for button in row:
                verified = signer.verify(button["callback_data"], USER)
                assert verified.user_id == USER

    def test_every_callback_payload_fits_telegrams_limit(self, bot, signer):
        """Over 64 bytes and Telegram drops the button at send time, silently."""
        from rivalforge.telegram.bot import Bot

        api = LoopbackAPI([message("/play")], [message("/start")])
        loop = Bot(api, bot, sleep=lambda _s: None)
        loop.poll_once()
        loop.poll_once()
        for _, keyboard in api.sent:
            for row in keyboard or []:
                for button in row:
                    assert len(button["callback_data"].encode("utf-8")) <= 64


class TestWiredThroughTheCompositionRoot:
    """The bot built the way `rivalforge telegram` builds it.

    The tests above hand-build an `Application` so they can inject a fake
    wallet provider. This one goes through `build_application`, which is what
    actually runs in production -- so a change to the composition root that
    breaks the bot fails here rather than on a live deployment.
    """

    @pytest.fixture
    def wired(self, tmp_path):
        from rivalforge.cli.wiring import build_application

        env = {
            "RIVALFORGE_FEATURE_TELEGRAM_BOT": "1",
            "RIVALFORGE_SESSION_FILE": str(tmp_path / "sessions.json"),
            "XDG_STATE_HOME": str(tmp_path / "state"),
        }
        app = build_application(env=env)
        return BotHandlers(app, signer=CallbackSigner(KEY))

    def test_the_default_deployment_is_playable_without_a_wallet(self, wired):
        """The largest drop-off in this genre is asking for a wallet first."""
        actions = wired.handle(message("/play"))
        assert isinstance(actions[0], SendMessage)
        assert actions[0].keyboard

    def test_wallet_verification_stays_off_unless_it_is_turned_on(self, wired):
        """Nothing reaches a chain on a fresh deployment with no configuration."""
        assert wired._app.features.enabled("wallet_verification") is False
        actions = wired.handle(message("/roster"))
        assert "Connect a wallet first" in texts(actions)
