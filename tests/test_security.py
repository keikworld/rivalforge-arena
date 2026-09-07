"""Tests for the validation and redaction primitives."""

from __future__ import annotations

import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from rivalforge.security.redaction import (
    REDACTED,
    RedactionFilter,
    redact,
    short_address,
)
from rivalforge.security.validation import (
    MAX_DISPLAY_NAME_LENGTH,
    ValidationError,
    b58decode,
    sanitize_display_name,
    validate_choice,
    validate_float,
    validate_identifier,
    validate_int,
    validate_mint_address,
    validate_text_field,
)

# A real, well-known Solana mint address shape (32 bytes, base58).
VALID_MINT = "So11111111111111111111111111111111111111112"


class TestMintAddress:
    def test_accepts_a_valid_address(self):
        assert validate_mint_address(VALID_MINT) == VALID_MINT

    @pytest.mark.parametrize(
        "bad",
        [
            "",                      # empty
            "abc",                   # far too short
            "1" * 45,                # too long
            "0" * 32,                # '0' is not in the base58 alphabet
            "O" * 32,                # nor is 'O'
            "I" * 32,                # nor 'I'
            "l" * 32,                # nor 'l'
            "So1111111111111111111111111111111111111111+",  # symbol
        ],
    )
    def test_rejects_malformed_addresses(self, bad):
        with pytest.raises(ValidationError):
            validate_mint_address(bad)

    @pytest.mark.parametrize("bad", [None, 123, b"bytes", ["list"], {"a": 1}, True])
    def test_rejects_non_strings(self, bad):
        with pytest.raises(ValidationError):
            validate_mint_address(bad)

    def test_rejects_an_address_that_decodes_to_the_wrong_length(self):
        # 32 base58 chars that decode to fewer than 32 bytes.
        with pytest.raises(ValidationError, match="bytes"):
            validate_mint_address("2" * 32)

    def test_b58_leading_ones_are_zero_bytes(self):
        assert b58decode("1") == b"\x00"
        assert b58decode("11") == b"\x00\x00"
        assert len(b58decode("1" * 32)) == 32


class TestDisplayName:
    def test_trims_and_collapses_whitespace(self):
        assert sanitize_display_name("  Frost   Knight \n") == "Frost Knight"

    def test_strips_zero_width_and_control_characters(self):
        # A zero-width joiner and a right-to-left override, both of which can
        # be used to spoof another player's name.
        assert sanitize_display_name("Fro‍st‮") == "Frost"

    def test_normalises_compatibility_forms(self):
        # Fullwidth 'A' normalises to ASCII 'A' under NFKC, so two names that
        # render identically cannot be registered as different players.
        assert sanitize_display_name("Ａbc") == "Abc"

    def test_caps_length(self):
        assert len(sanitize_display_name("x" * 500)) == MAX_DISPLAY_NAME_LENGTH

    @pytest.mark.parametrize("bad", ["", "   ", "‍‍", "\x00\x01"])
    def test_rejects_names_with_nothing_printable(self, bad):
        with pytest.raises(ValidationError):
            sanitize_display_name(bad)

    @given(st.text(min_size=1))
    def test_output_is_always_bounded_and_control_free(self, raw):
        try:
            cleaned = sanitize_display_name(raw)
        except ValidationError:
            return  # rejecting is a valid outcome
        assert 0 < len(cleaned) <= MAX_DISPLAY_NAME_LENGTH
        assert all(ord(c) >= 0x20 for c in cleaned)
        assert cleaned == cleaned.strip()


class TestNumbers:
    def test_bool_is_not_an_integer(self):
        # bool subclasses int in Python; letting True through as 1 has caused
        # real scoring bugs, so it is rejected explicitly.
        with pytest.raises(ValidationError):
            validate_int(True, field="x", minimum=0, maximum=10)
        with pytest.raises(ValidationError):
            validate_float(False, field="x", minimum=0, maximum=10)

    def test_bounds_are_inclusive(self):
        assert validate_int(0, field="x", minimum=0, maximum=10) == 0
        assert validate_int(10, field="x", minimum=0, maximum=10) == 10

    @pytest.mark.parametrize("bad", [-1, 11])
    def test_rejects_out_of_range(self, bad):
        with pytest.raises(ValidationError):
            validate_int(bad, field="x", minimum=0, maximum=10)

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_rejects_nan_and_infinities(self, bad):
        # NaN poisons every comparison it touches; an infinity in a damage
        # formula ends a match in a way no test would predict.
        with pytest.raises(ValidationError):
            validate_float(bad, field="x", minimum=0, maximum=10)


class TestIdentifiersAndChoices:
    @pytest.mark.parametrize("good", ["a", "blazing_rift", "x9", "a_1_b"])
    def test_accepts_snake_case(self, good):
        assert validate_identifier(good) == good

    @pytest.mark.parametrize(
        "bad", ["", "A", "Blazing_Rift", "1abc", "with-dash", "with space", "x" * 65]
    )
    def test_rejects_everything_else(self, bad):
        with pytest.raises(ValidationError):
            validate_identifier(bad)

    def test_choice_returns_the_allowed_member(self):
        assert validate_choice("b", field="x", allowed=["a", "b"]) == "b"

    def test_choice_rejects_outsiders(self):
        with pytest.raises(ValidationError, match="must be one of"):
            validate_choice("c", field="x", allowed=["a", "b"])

    def test_text_field_rejects_control_characters(self):
        with pytest.raises(ValidationError, match="control"):
            validate_text_field("bad\x07text", field="x", max_length=50)


class TestRedaction:
    @pytest.mark.parametrize(
        "line",
        [
            "private_key=abc123xyz",
            'password: "hunter2"',
            '{"api_key": "sk-live-0000"}',
            "authorization: Bearer abcdefghijklmnop",
            "secret = topsecretvalue",
        ],
    )
    def test_secret_values_are_removed(self, line):
        out = redact(line)
        assert REDACTED in out
        for leak in ("abc123xyz", "hunter2", "sk-live-0000", "abcdefghijklmnop", "topsecretvalue"):
            assert leak not in out

    def test_addresses_are_truncated_not_removed(self):
        # Public but personal: a log full of full addresses is a map of who
        # plays what. Truncated keeps lines correlatable without enumerating.
        out = redact(f"fighter drawn for {VALID_MINT}")
        assert VALID_MINT not in out
        assert "So11...1112" in out

    def test_jwt_is_removed(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
        assert token not in redact(f"token {token}")

    def test_pem_block_is_removed(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----"
        out = redact(f"key: {pem}")
        assert "MIIBVQIBADAN" not in out

    def test_short_address_is_stable(self):
        assert short_address(VALID_MINT) == short_address(VALID_MINT)
        assert short_address("abc") == "abc"

    def test_filter_redacts_a_real_log_record(self, caplog):
        logger = logging.getLogger("rivalforge.test.redaction")
        logger.propagate = True
        handler = logging.StreamHandler()
        handler.addFilter(RedactionFilter())

        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname=__file__, lineno=1,
            msg="wallet %s connected with api_key=%s",
            args=(VALID_MINT, "supersecret"), exc_info=None,
        )
        assert RedactionFilter().filter(record) is True
        rendered = record.getMessage()
        assert "supersecret" not in rendered
        assert VALID_MINT not in rendered
