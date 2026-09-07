"""Tests for the Telegram security primitives.

Each class here corresponds to one of the four threats named in
`telegram/security.py`. The point of the module is to be the one place those
defences live, and the point of this file is to prove each one actually holds.
"""

from __future__ import annotations

import pytest

from rivalforge.security.validation import ValidationError
from rivalforge.telegram.security import (
    MAX_CALLBACK_BYTES,
    CallbackError,
    CallbackSigner,
    RateLimited,
    RateLimiter,
    WrongChatType,
    clean_text,
    escape_code,
    escape_html,
    escape_markdown,
    require_private_chat,
    safe_name,
    validate_chat_id,
    validate_user_id,
)


class TestEscaping:
    """Threat 1: an NFT name is attacker-controlled text in a formatted message."""

    def test_every_markdown_special_is_escaped(self):
        for char in r"_*[]()~`>#+-=|{}.!":
            escaped = escape_markdown(char)
            assert escaped == f"\\{char}", f"{char!r} was not escaped"

    def test_a_phishing_link_cannot_survive_escaping(self):
        """The whole reason this module exists.

        Minting a token called `[Claim your airdrop](https://evil.example)`
        costs a few cents. Rendered unescaped it is a clickable link inside a
        message the bot sent, which is a phishing page with our name on it.
        """
        hostile = "[Claim your airdrop](https://evil.example)"
        rendered = escape_markdown(hostile)
        assert "](" not in rendered
        assert rendered.startswith("\\[")

    def test_html_escaping_covers_tag_and_attribute_breakouts(self):
        assert escape_html('<a href="x">&</a>') == (
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        )

    def test_code_escaping_covers_exactly_the_two_that_matter(self):
        """Inside a fenced block, only a backtick and a backslash are syntax."""
        assert escape_code("a`b") == "a\\`b"
        assert escape_code("a\\b") == "a\\\\b"
        # Everything else is literal in there, and escaping it would show the
        # player a backslash they did not type.
        assert escape_code("[a](b) *c* _d_") == "[a](b) *c* _d_"

    def test_a_backtick_run_cannot_close_a_fenced_block(self):
        hostile = "```\nnot really the end\n```"
        assert "```" not in escape_code(hostile)


class TestCleanText:
    def test_bidi_and_zero_width_characters_are_removed(self):
        """A right-to-left override makes one name render as another."""
        assert "‮" not in clean_text("gnp‮.exe")
        assert "​" not in clean_text("a​b")

    def test_a_newline_cannot_break_a_table_apart(self):
        assert "\n" not in clean_text("row one\nrow two")

    def test_long_names_are_truncated(self):
        cleaned = clean_text("A" * 4000, limit=40)
        assert len(cleaned) == 40

    def test_nothing_printable_falls_back_rather_than_raising(self):
        """A hostile name must not be able to raise inside a render."""
        assert clean_text("​​") == "(unnamed)"

    def test_safe_name_is_clean_then_escaped(self):
        assert safe_name("a_b‮c") == "a\\_bc"


class TestIdentifiers:
    def test_a_user_id_must_be_a_positive_integer(self):
        assert validate_user_id(42) == 42
        for bad in (0, -1, "42", None, 1.5, True):
            with pytest.raises(ValidationError):
                validate_user_id(bad)

    def test_group_chat_ids_are_negative_and_allowed(self):
        assert validate_chat_id(-1001234567890) == -1001234567890


class TestChatType:
    """Threat 3: a challenge posted in a group is a challenge everyone reads."""

    def test_a_private_chat_is_accepted(self):
        assert require_private_chat({"id": 7, "type": "private"}) == 7

    @pytest.mark.parametrize("kind", ["group", "supergroup", "channel", "", None])
    def test_everything_else_is_refused(self, kind):
        with pytest.raises(WrongChatType):
            require_private_chat({"id": -100, "type": kind})

    def test_a_missing_chat_is_refused_rather_than_assumed_private(self):
        with pytest.raises(WrongChatType):
            require_private_chat(None)


class TestCallbackSigner:
    """Threat 2: callback_data is user input, whatever produced it."""

    def test_a_signed_payload_round_trips(self):
        signer = CallbackSigner(b"k" * 32)
        data = signer.sign("st", "strike", 99)
        callback = signer.verify(data, 99)
        assert (callback.action, callback.argument, callback.user_id) == ("st", "strike", 99)

    def test_a_payload_from_another_user_does_not_verify(self):
        """The binding that stops a button being lifted from someone else's chat."""
        signer = CallbackSigner(b"k" * 32)
        data = signer.sign("st", "strike", 99)
        with pytest.raises(CallbackError):
            signer.verify(data, 100)

    def test_a_forged_payload_does_not_verify(self):
        signer = CallbackSigner(b"k" * 32)
        with pytest.raises(CallbackError):
            signer.verify("st|strike|AAAAAAAAAAAAAAAA", 99)

    def test_tampering_with_the_argument_invalidates_the_signature(self):
        signer = CallbackSigner(b"k" * 32)
        action, argument, signature = signer.sign("st", "strike", 99).split("|")
        with pytest.raises(CallbackError):
            signer.verify(f"{action}|guard|{signature}", 99)

    def test_another_key_does_not_verify(self):
        data = CallbackSigner(b"k" * 32).sign("st", "strike", 99)
        with pytest.raises(CallbackError):
            CallbackSigner(b"j" * 32).verify(data, 99)

    @pytest.mark.parametrize("bad", ["", None, 5, "one|two", "a|b|c|d", b"st|strike|x"])
    def test_malformed_payloads_are_refused(self, bad):
        with pytest.raises(CallbackError):
            CallbackSigner(b"k" * 32).verify(bad, 99)

    def test_oversized_payloads_are_refused_before_any_parsing(self):
        with pytest.raises(CallbackError):
            CallbackSigner(b"k" * 32).verify("x" * (MAX_CALLBACK_BYTES + 1), 99)

    def test_signing_stays_inside_telegrams_limit(self):
        signer = CallbackSigner(b"k" * 32)
        data = signer.sign("st", "strike", 9_999_999_999)
        assert len(data.encode("utf-8")) <= MAX_CALLBACK_BYTES

    def test_an_oversized_payload_raises_rather_than_failing_silently(self):
        """Telegram drops an over-long callback_data at send time with no error."""
        signer = CallbackSigner(b"k" * 32)
        with pytest.raises(ValueError):
            signer.sign("action", "x" * 60, 1)

    def test_the_separator_cannot_be_smuggled_into_a_field(self):
        signer = CallbackSigner(b"k" * 32)
        with pytest.raises(ValueError):
            signer.sign("st", "strike|guard", 1)

    def test_a_short_key_is_refused(self):
        with pytest.raises(ValueError):
            CallbackSigner(b"short")

    def test_a_generated_key_is_not_shared_between_instances(self):
        data = CallbackSigner().sign("st", "strike", 1)
        with pytest.raises(CallbackError):
            CallbackSigner().verify(data, 1)


class TestRateLimiter:
    """Threat 4: a bot endpoint is reachable by anyone who finds it."""

    def test_a_burst_is_allowed_then_refused(self):
        limiter = RateLimiter(capacity=3, refill_per_second=1.0)
        for _ in range(3):
            limiter.check(1, now=0.0)
        with pytest.raises(RateLimited):
            limiter.check(1, now=0.0)

    def test_the_bucket_refills(self):
        limiter = RateLimiter(capacity=2, refill_per_second=1.0)
        limiter.check(1, now=0.0)
        limiter.check(1, now=0.0)
        with pytest.raises(RateLimited):
            limiter.check(1, now=0.0)
        limiter.check(1, now=1.5)

    def test_one_user_cannot_exhaust_another(self):
        limiter = RateLimiter(capacity=1, refill_per_second=1.0)
        limiter.check(1, now=0.0)
        limiter.check(2, now=0.0)  # a different bucket entirely

    def test_the_limiter_is_itself_bounded(self):
        """Otherwise the defence against flooding *is* the memory exhaustion."""
        limiter = RateLimiter(capacity=5, refill_per_second=1.0, max_users=10)
        for user in range(500):
            limiter.check(user, now=0.0)
        assert len(limiter) <= 10

    def test_stale_buckets_are_dropped_before_active_ones(self):
        limiter = RateLimiter(capacity=2, refill_per_second=1.0, max_users=2)
        limiter.check(1, now=0.0)
        limiter.check(2, now=100.0)
        limiter.check(3, now=100.0)
        assert len(limiter) <= 2

    def test_bad_configuration_is_refused(self):
        for kwargs in ({"capacity": 0}, {"refill_per_second": 0}, {"max_users": 0}):
            with pytest.raises(ValueError):
                RateLimiter(**kwargs)
