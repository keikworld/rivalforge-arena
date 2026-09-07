"""Security tests for wallet authentication.

Organised by attack rather than by function, because the question that matters
is not "does verify() work" but "what can someone do to this endpoint".

Real ed25519 keypairs are used throughout. A signature test that mocks the
signature proves nothing.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from rivalforge.auth.audit import AuditEvent, AuditTrail, InMemoryAuditSink
from rivalforge.auth.challenge import (
    AuthError,
    Challenge,
    ChallengeService,
    _assert_not_transaction_shaped,
    build_message,
)
from rivalforge.auth.service import MAX_ROSTER, OwnershipRequired, WalletService
from rivalforge.auth.session import SessionService
from rivalforge.auth.store import (
    InMemoryChallengeStore,
    MAX_PER_WALLET,
    RateLimitExceeded,
)
from rivalforge.content.loader import load_content
from rivalforge.plugins.adapters import FakeWalletProvider, FixedClock
from rivalforge.plugins.ports import OwnedNFT, OwnershipResult
from rivalforge.security.validation import ValidationError, b58encode

nacl_signing = pytest.importorskip("nacl.signing")

DOMAIN = "rivalforge.game"
URI = "https://rivalforge.game"


class Wallet:
    """A real ed25519 keypair, standing in for a player's wallet."""

    def __init__(self, seed: bytes = b"\x01" * 32) -> None:
        self.key = nacl_signing.SigningKey(seed)
        self.address = b58encode(bytes(self.key.verify_key))

    def sign(self, message: str) -> str:
        return b58encode(self.key.sign(message.encode("utf-8")).signature)


@pytest.fixture
def clock():
    return FixedClock(datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc))


@pytest.fixture
def store():
    return InMemoryChallengeStore()


@pytest.fixture
def challenges(store, clock):
    return ChallengeService(store, clock, domain=DOMAIN, uri=URI)


@pytest.fixture
def wallet():
    return Wallet()


@pytest.fixture
def other_wallet():
    return Wallet(seed=b"\x02" * 32)


# ==========================================================================
# The core guarantee: this cannot drain a wallet
# ==========================================================================


class TestCannotDrainAWallet:
    def test_no_module_in_the_package_can_build_a_transaction(self):
        """The strongest available statement: there is no code path here that
        constructs, requests or relays a Solana transaction."""
        import pathlib  # noqa: PLC0415

        import rivalforge  # noqa: PLC0415

        root = pathlib.Path(rivalforge.__file__).parent
        banned = (
            "signTransaction", "sign_transaction", "sendTransaction",
            "send_transaction", "Transaction(", "partialSign", "signAllTransactions",
        )
        offenders = []
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in banned:
                if needle in text:
                    offenders.append(f"{path.name}: {needle}")
        assert not offenders, f"transaction-building code found: {offenders}"

    def test_no_module_asks_for_key_material(self):
        import pathlib  # noqa: PLC0415

        import rivalforge  # noqa: PLC0415

        root = pathlib.Path(rivalforge.__file__).parent
        banned = ("seed_phrase", "mnemonic", "secretKey", "secret_key", "privateKey")
        offenders = []
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for needle in banned:
                # The redaction module names these deliberately, to scrub them.
                if needle in text and path.name != "redaction.py":
                    offenders.append(f"{path.name}: {needle}")
        assert not offenders, f"key-material handling found: {offenders}"

    def test_the_signed_message_cannot_deserialise_as_a_transaction(self, challenges, wallet):
        """A Solana transaction begins with a compact-u16 signature count -- a
        byte in 1..255, never a printable character. Constraining the message to
        printable ASCII starting with an alphanumeric closes the
        message-as-transaction blind-signing attack."""
        message = challenges.issue(wallet.address).message
        raw = message.encode("utf-8")
        assert raw[0] >= 0x20, "first byte must be printable, not a signature count"
        assert message[0].isalnum()
        assert all(0x20 <= b <= 0x7E or b == 0x0A for b in raw)

    @pytest.mark.parametrize("bad", [
        "\x01\x00\x00 transaction-ish",
        "",
        " leading space",
        "\x00binary",
    ])
    def test_transaction_shaped_messages_are_refused(self, bad):
        with pytest.raises(ValueError):
            _assert_not_transaction_shaped(bad)

    def test_the_message_tells_the_player_it_is_not_a_transaction(self, challenges, wallet):
        """The player reading their wallet prompt is the last line of defence
        and deserves a sentence they can act on."""
        message = challenges.issue(wallet.address).message
        assert "signature request only" in message
        assert "does not move funds" in message
        assert DOMAIN in message.splitlines()[0]


# ==========================================================================
# Signature verification
# ==========================================================================


class TestSignatureVerification:
    def test_a_correct_signature_authenticates(self, challenges, wallet):
        challenge = challenges.issue(wallet.address)
        result = challenges.verify(challenge.nonce, wallet.sign(challenge.message))
        assert result.wallet == wallet.address

    def test_a_signature_from_another_key_is_rejected(
        self, challenges, wallet, other_wallet
    ):
        """The whole point: holding the address is not holding the key."""
        challenge = challenges.issue(wallet.address)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, other_wallet.sign(challenge.message))

    def test_a_signature_over_different_text_is_rejected(self, challenges, wallet):
        challenge = challenges.issue(wallet.address)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, wallet.sign("something else entirely"))

    def test_a_signature_over_a_tampered_message_is_rejected(self, challenges, wallet):
        """The verifier rebuilds the message from server state, so signing an
        edited copy proves nothing."""
        challenge = challenges.issue(wallet.address)
        tampered = challenge.message.replace(DOMAIN, "evil.example")
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, wallet.sign(tampered))

    @pytest.mark.parametrize("bad", [
        "", "not-base58-0OIl", "AAAA", b58encode(b"\x00" * 63), b58encode(b"\x00" * 65),
    ])
    def test_malformed_signatures_are_rejected_cleanly(self, challenges, wallet, bad):
        """An entry point must never crash on bad input."""
        challenge = challenges.issue(wallet.address)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, bad)

    @pytest.mark.parametrize("bad", [None, 123, [], {}, b"bytes"])
    def test_non_string_inputs_are_rejected_cleanly(self, challenges, wallet, bad):
        challenge = challenges.issue(wallet.address)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, bad)
        with pytest.raises(AuthError):
            challenges.verify(bad, "x")

    def test_oversized_inputs_are_refused_before_any_work(self, challenges):
        with pytest.raises(AuthError):
            challenges.verify("n" * 500, "s" * 5000)


# ==========================================================================
# Replay
# ==========================================================================


class TestReplay:
    def test_a_nonce_works_exactly_once(self, challenges, wallet):
        challenge = challenges.issue(wallet.address)
        signature = wallet.sign(challenge.message)
        challenges.verify(challenge.nonce, signature)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, signature)

    def test_a_failed_attempt_still_burns_the_nonce(self, challenges, wallet, other_wallet):
        """Consuming before verifying stops an attacker grinding signatures
        against one live challenge."""
        challenge = challenges.issue(wallet.address)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, other_wallet.sign(challenge.message))
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, wallet.sign(challenge.message))

    def test_an_unknown_nonce_is_rejected(self, challenges):
        with pytest.raises(AuthError):
            challenges.verify("0" * 64, b58encode(b"\x00" * 64))

    def test_concurrent_verification_admits_only_one_winner(self, challenges, wallet):
        """`consume` is atomic, so two racing requests cannot both succeed."""
        challenge = challenges.issue(wallet.address)
        signature = wallet.sign(challenge.message)
        wins: list[bool] = []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            try:
                challenges.verify(challenge.nonce, signature)
                wins.append(True)
            except AuthError:
                pass

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(wins) == 1, f"{len(wins)} concurrent verifications succeeded"

    def test_nonces_are_unique_and_unpredictable(self, challenges, wallet):
        seen = {challenges.issue(wallet.address).nonce for _ in range(4)}
        assert len(seen) == 4
        for nonce in seen:
            assert len(nonce) == 64  # 32 bytes, hex


# ==========================================================================
# Expiry and clock
# ==========================================================================


class TestExpiry:
    def test_an_expired_challenge_is_rejected(self, challenges, clock, wallet):
        challenge = challenges.issue(wallet.address)
        signature = wallet.sign(challenge.message)
        clock.advance(6 * 60)
        with pytest.raises(AuthError):
            challenges.verify(challenge.nonce, signature)

    def test_a_challenge_just_inside_the_window_still_works(self, challenges, clock, wallet):
        challenge = challenges.issue(wallet.address)
        signature = wallet.sign(challenge.message)
        clock.advance(4 * 60)
        assert challenges.verify(challenge.nonce, signature).wallet == wallet.address

    def test_expiry_is_in_the_signed_text(self, challenges, wallet):
        challenge = challenges.issue(wallet.address)
        assert "Expiration Time:" in challenge.message
        assert challenge.expires_at > challenge.issued_at

    def test_purging_removes_expired_challenges(self, store, challenges, clock, wallet):
        challenges.issue(wallet.address)
        assert len(store) == 1
        clock.advance(10 * 60)
        assert store.purge_expired(clock.now()) == 1
        assert len(store) == 0


# ==========================================================================
# Domain binding
# ==========================================================================


class TestDomainBinding:
    def test_a_challenge_from_another_domain_does_not_authenticate_here(
        self, store, clock, wallet
    ):
        """A signature captured by a phishing site must not be replayable."""
        evil = ChallengeService(store, clock, domain="evil.example", uri="https://evil.example")
        ours = ChallengeService(store, clock, domain=DOMAIN, uri=URI)
        challenge = evil.issue(wallet.address)
        with pytest.raises(AuthError):
            ours.verify(challenge.nonce, wallet.sign(challenge.message))

    def test_the_domain_is_the_first_thing_the_player_sees(self, challenges, wallet):
        first_line = challenges.issue(wallet.address).message.splitlines()[0]
        assert first_line.startswith(DOMAIN)

    @pytest.mark.parametrize("bad", ["", "has space", "\x01evil", None])
    def test_a_malformed_domain_is_refused_at_construction(self, store, clock, bad):
        with pytest.raises((ValueError, TypeError)):
            ChallengeService(store, clock, domain=bad, uri=URI)


# ==========================================================================
# Denial of service
# ==========================================================================


class TestDenialOfService:
    def test_one_wallet_cannot_hold_unlimited_challenges(self, challenges, wallet):
        for _ in range(MAX_PER_WALLET):
            challenges.issue(wallet.address)
        with pytest.raises(RateLimitExceeded):
            challenges.issue(wallet.address)

    def test_the_store_is_bounded_and_evicts(self, clock):
        small = InMemoryChallengeStore(max_challenges=10, max_per_wallet=100)
        service = ChallengeService(small, clock, domain=DOMAIN, uri=URI)
        for index in range(40):
            service.issue(Wallet(seed=bytes([index % 251 + 1]) * 32).address)
        assert len(small) <= 10

    def test_expired_challenges_free_the_per_wallet_slot(self, challenges, clock, wallet):
        """A player who abandons a few prompts must not be locked out."""
        for _ in range(MAX_PER_WALLET):
            challenges.issue(wallet.address)
        clock.advance(10 * 60)
        challenges.issue(wallet.address)  # must not raise

    def test_a_malformed_wallet_never_occupies_store_capacity(self, challenges, store):
        with pytest.raises(ValidationError):
            challenges.issue("not-a-wallet")
        assert len(store) == 0


# ==========================================================================
# Information disclosure
# ==========================================================================


class TestNoOracles:
    def test_every_failure_returns_the_same_public_message(
        self, challenges, wallet, other_wallet
    ):
        """Distinguishing 'no such nonce' from 'wrong key' from 'expired' is an
        enumeration oracle. All three read identically to the caller."""
        messages = set()

        challenge = challenges.issue(wallet.address)
        try:
            challenges.verify(challenge.nonce, other_wallet.sign(challenge.message))
        except AuthError as exc:
            messages.add(str(exc))

        try:
            challenges.verify("0" * 64, wallet.sign("x"))
        except AuthError as exc:
            messages.add(str(exc))

        try:
            challenges.verify("0" * 64, "not base58 !!")
        except AuthError as exc:
            messages.add(str(exc))

        assert len(messages) == 1, f"failures are distinguishable: {messages}"

    def test_the_internal_reason_is_available_for_operators(self, challenges):
        """Generic outward, specific inward -- the audit trail needs the detail."""
        try:
            challenges.verify("0" * 64, b58encode(b"\x00" * 64))
        except AuthError as exc:
            assert exc.internal_reason
            assert exc.internal_reason != str(exc)


# ==========================================================================
# Sessions
# ==========================================================================


class TestSessions:
    def test_a_token_resolves_to_its_wallet(self, clock, wallet):
        sessions = SessionService(clock)
        issued = sessions.issue(wallet.address)
        assert sessions.resolve(issued.token).wallet == wallet.address

    def test_tokens_are_stored_hashed_not_in_plaintext(self, clock, wallet):
        """A dump of the session store must not hand the reader live sessions."""
        sessions = SessionService(clock)
        issued = sessions.issue(wallet.address)
        assert issued.session.token_hash != issued.token
        assert issued.token not in repr(issued.session)
        assert len(issued.session.token_hash) == 64  # sha256 hex

    def test_sessions_expire(self, clock, wallet):
        sessions = SessionService(clock, ttl=timedelta(minutes=10))
        issued = sessions.issue(wallet.address)
        clock.advance(11 * 60)
        assert sessions.resolve(issued.token) is None

    @pytest.mark.parametrize("bad", [None, "", 123, "x" * 1000, b"bytes"])
    def test_malformed_tokens_resolve_to_nothing_without_raising(self, clock, bad):
        assert SessionService(clock).resolve(bad) is None

    def test_revoke_ends_a_session(self, clock, wallet):
        sessions = SessionService(clock)
        issued = sessions.issue(wallet.address)
        assert sessions.revoke(issued.token) is True
        assert sessions.resolve(issued.token) is None
        assert sessions.revoke(issued.token) is False

    def test_revoking_a_wallet_ends_all_its_sessions(self, clock, wallet, other_wallet):
        sessions = SessionService(clock)
        mine = [sessions.issue(wallet.address) for _ in range(3)]
        theirs = sessions.issue(other_wallet.address)
        assert sessions.revoke_wallet(wallet.address) == 3
        assert all(sessions.resolve(s.token) is None for s in mine)
        assert sessions.resolve(theirs.token) is not None

    def test_tokens_are_unique(self, clock, wallet):
        sessions = SessionService(clock)
        assert len({sessions.issue(wallet.address).token for _ in range(20)}) == 20

    def test_the_store_is_bounded(self, clock):
        sessions = SessionService(clock, max_sessions=5)
        for index in range(30):
            sessions.issue(Wallet(seed=bytes([index % 251 + 1]) * 32).address)
        assert len(sessions) <= 5


# ==========================================================================
# The wired-together service
# ==========================================================================


@pytest.fixture
def content():
    return load_content()


@pytest.fixture
def wired(challenges, clock, content, wallet):
    provider = FakeWalletProvider()
    sink = InMemoryAuditSink()
    service = WalletService(
        challenges,
        SessionService(clock),
        provider,
        AuditTrail(sink, clock),
        content,
    )
    return service, provider, sink


def _connect(service, wallet) -> str:
    challenge = service.begin(wallet.address)
    return service.complete(challenge.nonce, wallet.sign(challenge.message)).token


class TestWalletService:
    def test_the_happy_path(self, wired, wallet):
        service, provider, _ = wired
        token = _connect(service, wallet)
        assert service.wallet_for(token) == wallet.address

    def test_ownership_gates_playing_a_fighter(self, wired, wallet):
        service, provider, _ = wired
        mint = b58encode(b"\x07" * 32)
        token = _connect(service, wallet)

        with pytest.raises(OwnershipRequired, match="does not hold"):
            service.fighter_for(token, mint)

        provider.give(wallet.address, OwnedNFT(mint=mint, name="Mine", collection=None))
        assert service.fighter_for(token, mint).mint == mint

    def test_an_ownership_outage_fails_closed(self, wired, wallet, monkeypatch):
        """Refusing to check is not permission. This is the opposite of the
        rule for reading a roster, and deliberately so."""
        service, provider, _ = wired
        mint = b58encode(b"\x08" * 32)
        provider.give(wallet.address, OwnedNFT(mint=mint, name="Mine", collection=None))
        token = _connect(service, wallet)
        monkeypatch.setattr(
            provider, "verify_ownership",
            lambda w, m: OwnershipResult.unavailable("rpc down"),
        )
        with pytest.raises(OwnershipRequired, match="could not be confirmed"):
            service.fighter_for(token, mint)

    def test_no_session_means_no_fighter(self, wired):
        service, _, _ = wired
        with pytest.raises(AuthError):
            service.fighter_for("bogus-token", b58encode(b"\x09" * 32))

    def test_a_malformed_mint_is_rejected(self, wired, wallet):
        service, _, _ = wired
        token = _connect(service, wallet)
        with pytest.raises(ValidationError):
            service.fighter_for(token, "not-a-mint")

    def test_roster_is_capped(self, wired, wallet):
        service, provider, _ = wired
        for index in range(80):
            provider.give(
                wallet.address,
                OwnedNFT(mint=b58encode(bytes([index % 251 + 1]) * 32), name="n", collection=None),
            )
        token = _connect(service, wallet)
        assert len(service.roster(token, limit=999)) <= MAX_ROSTER

    def test_a_roster_outage_is_surfaced_not_hidden(self, wired, wallet, monkeypatch):
        """An empty roster during an outage would read as 'your NFTs are gone'."""
        service, provider, _ = wired
        token = _connect(service, wallet)
        monkeypatch.setattr(
            provider, "list_owned",
            lambda w, *, limit=100: (_ for _ in ()).throw(RuntimeError("rpc down")),
        )
        with pytest.raises(RuntimeError, match="could not read holdings"):
            service.roster(token)

    def test_disconnect_ends_the_session(self, wired, wallet):
        service, _, sink = wired
        token = _connect(service, wallet)
        assert service.disconnect(token) is True
        with pytest.raises(AuthError):
            service.wallet_for(token)
        assert any(r.event is AuditEvent.SESSION_REVOKED for r in sink.records())

    def test_rate_limiting_is_audited(self, wired, wallet):
        service, _, sink = wired
        for _ in range(MAX_PER_WALLET):
            service.begin(wallet.address)
        with pytest.raises(RateLimitExceeded):
            service.begin(wallet.address)
        assert any(r.event is AuditEvent.CHALLENGE_RATE_LIMITED for r in sink.records())


# ==========================================================================
# Audit trail
# ==========================================================================


class TestAuditTrail:
    def test_the_full_flow_is_recorded_in_order(self, wired, wallet):
        service, provider, sink = wired
        mint = b58encode(b"\x0a" * 32)
        provider.give(wallet.address, OwnedNFT(mint=mint, name="Mine", collection=None))
        token = _connect(service, wallet)
        service.fighter_for(token, mint)

        events = [r.event for r in sink.records()]
        assert events == [
            AuditEvent.CHALLENGE_ISSUED,
            AuditEvent.AUTH_SUCCEEDED,
            AuditEvent.OWNERSHIP_VERIFIED,
        ]

    def test_failures_are_recorded_with_their_real_reason(self, wired, wallet, other_wallet):
        service, _, sink = wired
        challenge = service.begin(wallet.address)
        with pytest.raises(AuthError):
            service.complete(challenge.nonce, other_wallet.sign(challenge.message))
        failed = [r for r in sink.records() if r.event is AuditEvent.AUTH_FAILED]
        assert failed and failed[0].reason

    def test_records_hold_no_secrets(self, wired, wallet):
        """Signatures, tokens, token hashes and challenge text must never
        reach the audit trail."""
        service, _, sink = wired
        challenge = service.begin(wallet.address)
        signature = wallet.sign(challenge.message)
        connected = service.complete(challenge.nonce, signature)
        blob = " ".join(f"{r.event.value} {r.wallet} {r.outcome} {r.reason}" for r in sink.records())
        assert signature not in blob
        assert connected.token not in blob
        assert challenge.nonce not in blob
        assert "sign in with your Solana account" not in blob

    def test_records_hold_no_network_identifiers(self, wired, wallet):
        """No IP, user agent, device or location -- data we do not have cannot
        leak and cannot be subpoenaed."""
        service, _, sink = wired
        _connect(service, wallet)
        for record in sink.records():
            fields = set(record.__slots__)
            assert not fields & {"ip", "ip_address", "user_agent", "device", "location"}

    def test_the_wallet_is_kept_because_the_trail_needs_it(self, wired, wallet):
        service, _, sink = wired
        _connect(service, wallet)
        assert any(r.wallet == wallet.address for r in sink.records())

    def test_the_redacted_form_truncates_the_wallet_for_logs(self, wired, wallet):
        """Audit storage keeps the full address; the log line never does."""
        service, _, sink = wired
        _connect(service, wallet)
        for record in sink.records():
            assert wallet.address not in record.redacted()

    def test_a_failing_sink_never_breaks_the_thing_it_audits(self, challenges, clock, content, wallet):
        class BrokenSink:
            name = "broken"
            durable = False

            def write(self, record):
                raise RuntimeError("audit backend down")

        service = WalletService(
            challenges, SessionService(clock), FakeWalletProvider(),
            AuditTrail(BrokenSink(), clock), content,
        )
        token = _connect(service, wallet)  # must still work
        assert service.wallet_for(token) == wallet.address

    def test_the_sink_is_bounded(self, clock):
        sink = InMemoryAuditSink(max_records=10)
        trail = AuditTrail(sink, clock)
        for _ in range(50):
            trail.record(AuditEvent.AUTH_FAILED, outcome="rejected")
        assert len(sink) == 10

    def test_reasons_are_length_capped(self, clock):
        sink = InMemoryAuditSink()
        AuditTrail(sink, clock).record(
            AuditEvent.AUTH_FAILED, outcome="rejected", reason="x" * 5000
        )
        assert len(sink.records()[0].reason) <= 120
