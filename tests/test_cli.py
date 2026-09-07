"""Tests for the terminal client and the renderer.

The renderer is pure string functions, so it is tested like any other pure
code. The client is tested through `main()` with piped stdin, which is the same
path a player takes.
"""

from __future__ import annotations

import pytest

from rivalforge.cli.main import main
from rivalforge.cli.render import bp_bar, render_events, render_fighter, render_outcome
from rivalforge.content.loader import load_content
from rivalforge.content.schema import Element, Stance
from rivalforge.engine import balance
from rivalforge.engine.fighter import Fighter, derive_fighter
from rivalforge.engine.match import Event, EventKind, Match, Outcome, Side
from rivalforge.engine.rng import RNG

MINT = "So11111111111111111111111111111111111111112"
OTHER = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


@pytest.fixture(scope="module")
def content():
    return load_content()


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Point session and state storage at a temporary directory.

    Without this the suite reads whatever session file the developer happens
    to have from manual testing, which is exactly how a real ordering bug
    passed locally and failed in CI: `play --mint <bad>` checked for a session
    before validating the address, and a leftover session hid it.
    """
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("RIVALFORGE_SESSION_FILE", str(tmp_path / "sessions.json"))


class TestBpBar:
    def test_full_and_empty(self):
        assert bp_bar(100, 100, 10) == "[##########] 100/100"
        assert bp_bar(0, 100, 10) == "[..........]   0/100"

    def test_a_living_fighter_always_shows_a_segment(self):
        """1 BP and 0 BP must not look the same -- that reads as a bug."""
        assert bp_bar(1, 100, 10) != bp_bar(0, 100, 10)
        assert bp_bar(1, 100, 10).startswith("[#")

    def test_out_of_range_values_are_clamped(self):
        assert bp_bar(-50, 100, 10) == bp_bar(0, 100, 10)
        assert bp_bar(500, 100, 10) == bp_bar(100, 100, 10)

    def test_width_is_respected(self):
        for width in (4, 10, 24, 40):
            bar = bp_bar(50, 100, width)
            assert bar.count("#") + bar.count(".") == width


class TestRenderFighter:
    def test_never_prints_the_full_mint(self, content):
        """A rendered line can end up in a screenshot, a log or a chat. The
        address is public on-chain but a full one in every line is a map of
        who plays what."""
        line = render_fighter(derive_fighter(MINT, content))
        assert MINT not in line
        assert "So11...1112" in line

    def test_includes_stats_and_identity(self, content):
        line = render_fighter(derive_fighter(MINT, content, name="Ayla"))
        assert "Ayla" in line
        for label in ("PWR", "GRD", "FOC"):
            assert label in line


class TestRenderEvents:
    def test_every_event_kind_renders_without_crashing(self, content):
        """A renderer that raises on an unfamiliar event takes the whole match
        down. Every kind the engine can emit must produce something."""
        names = {Side.A: "Ayla", Side.B: "Bram"}
        rng = RNG(1)
        for kind in EventKind:
            event = Event(kind=kind, side=Side.A, amount=5, detail="burn")
            render_events([event], names, content, rng)  # must not raise

    def test_damage_and_stance_lines_name_the_fighter(self, content):
        names = {Side.A: "Ayla", Side.B: "Bram"}
        lines = render_events(
            [
                Event(EventKind.ROUND_START, amount=3),
                Event(EventKind.STANCE, side=Side.A, detail=Stance.STRIKE.value),
                Event(EventKind.DAMAGE, side=Side.B, amount=12),
            ],
            names, content, RNG(2),
        )
        joined = "\n".join(lines)
        assert "round 3" in joined
        assert "Ayla" in joined and "strike" in joined
        assert "Bram takes 12" in joined

    def test_narration_does_not_touch_the_match_stream(self, content):
        """Rendering must not perturb the match RNG, or a watched match would
        replay differently from an unwatched one."""
        def run(narrate: bool) -> list[str]:
            match = Match.create(
                derive_fighter(MINT, content), derive_fighter(OTHER, content),
                content.battlefield("blazing_rift"), content, seed=99,
            )
            narrator = RNG(99).fork("narration")
            names = {Side.A: "A", Side.B: "B"}
            while not match.is_over:
                events = match.submit({Side.A: "strike", Side.B: "guard"})
                if narrate:
                    render_events(events, names, content, narrator)
            return [str(e) for e in match.log]

        assert run(True) == run(False)


class TestRenderOutcome:
    def test_draw(self, content):
        text = render_outcome(
            Outcome(None, 12, {Side.A: 0, Side.B: 0}, "double knockout, level"),
            {Side.A: "A", Side.B: "B"}, content, RNG(1),
        )
        assert "DRAW" in text

    def test_victory_and_defeat_flavour_differ_by_viewer(self, content):
        outcome = Outcome(Side.A, 8, {Side.A: 20, Side.B: 0}, "knockout")
        names = {Side.A: "Ayla", Side.B: "Bram"}
        winner_view = render_outcome(outcome, names, content, RNG(4), viewer=Side.A)
        loser_view = render_outcome(outcome, names, content, RNG(4), viewer=Side.B)
        assert "Ayla wins" in winner_view and "Ayla wins" in loser_view
        assert winner_view != loser_view


class TestCli:
    def test_fighter_command(self, capsys):
        assert main(["fighter", MINT]) == 0
        out = capsys.readouterr().out
        assert "So11...1112" in out
        assert MINT not in out

    def test_fighter_command_rejects_a_bad_mint(self, capsys):
        assert main(["fighter", "not-a-mint"]) == 2
        assert "invalid input" in capsys.readouterr().err

    def test_watch_runs_a_full_match(self, capsys):
        assert main(["watch", "--a", "adaptive", "--b", "random", "--seed", "5"]) == 0
        out = capsys.readouterr().out
        assert "round 1" in out
        assert "wins in" in out or "DRAW" in out

    def test_watch_tally_mode(self, capsys):
        assert main([
            "watch", "--a", "adaptive", "--b", "aggressive",
            "--arena", "blazing_rift", "--seed", "1", "--rounds", "8",
        ]) == 0
        out = capsys.readouterr().out
        assert "8 matches" in out
        assert "draw" in out

    def test_watch_is_reproducible_for_a_seed(self, capsys):
        main(["watch", "--a", "adaptive", "--b", "random", "--seed", "31"])
        first = capsys.readouterr().out
        main(["watch", "--a", "adaptive", "--b", "random", "--seed", "31"])
        assert capsys.readouterr().out == first

    def test_unknown_arena_lists_the_valid_ones(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["watch", "--arena", "the_moon", "--seed", "1"])
        assert exc.value.code != 0
        assert "blazing_rift" in str(exc.value)

    def test_play_accepts_piped_stances_and_finishes(self, monkeypatch, capsys):
        answers = iter(["1"] * 60)
        monkeypatch.setattr("builtins.input", lambda *_: next(answers))
        assert main(["play", "--arena", "whisperwind_arena", "--seed", "3"]) == 0
        out = capsys.readouterr().out
        assert "wins in" in out or "DRAW" in out

    def test_play_reprompts_on_nonsense_then_accepts(self, monkeypatch, capsys):
        answers = iter(["banana", "7", ""] + ["strike"] * 60)
        monkeypatch.setattr("builtins.input", lambda *_: next(answers))
        assert main(["play", "--arena", "whisperwind_arena", "--seed", "3"]) == 0
        assert "Pick 1, 2 or 3" in capsys.readouterr().out

    def test_play_guards_on_end_of_input(self, monkeypatch, capsys):
        def raise_eof(*_):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        assert main(["play", "--arena", "whisperwind_arena", "--seed", "3"]) == 0
        assert "no input" in capsys.readouterr().out

    def test_play_quits_cleanly(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda *_: "q")
        assert main(["play", "--seed", "3"]) == 130
        assert "Bowing out" in capsys.readouterr().out

    def test_play_without_a_wallet_uses_the_starter(self, monkeypatch, capsys):
        """No wallet must be required to reach the first match."""
        answers = iter(["1"] * 60)
        monkeypatch.setattr("builtins.input", lambda *_: next(answers))
        assert main(["play", "--arena", "whisperwind_arena", "--seed", "3"]) == 0
        assert "Recruit" in capsys.readouterr().out

    def test_play_rejects_a_bad_mint_before_starting(self, capsys):
        """Validation precedes authorisation.

        A malformed mint is malformed whether or not anyone is signed in.
        Reporting "connect a wallet first" for a typo would send the player
        down entirely the wrong path -- which is what this did until CI, on a
        clean checkout with no session file, caught it.
        """
        assert main(["play", "--mint", "nope"]) == 2
        assert "invalid input" in capsys.readouterr().err

    def test_a_bad_mint_is_rejected_even_with_a_live_session(self, capsys):
        """The same, with the other branch of the condition exercised."""
        assert main(["play", "--mint", "nope", "--unverified"]) == 2
        assert "invalid input" in capsys.readouterr().err

    def test_a_supplied_name_is_sanitized(self, monkeypatch, capsys):
        answers = iter(["1"] * 60)
        monkeypatch.setattr("builtins.input", lambda *_: next(answers))
        main([
            "play", "--arena", "whisperwind_arena", "--seed", "3",
            "--name", "  Frost‍Knight  ",
        ])
        out = capsys.readouterr().out
        assert "FrostKnight" in out
        assert "‍" not in out


class TestTelegramCommand:
    """The CLI entry point for the bot. The bot itself is tested elsewhere."""

    def test_it_refuses_to_run_while_the_feature_is_off(self, capsys, monkeypatch):
        """Nothing that reaches a third party runs without its toggle."""
        monkeypatch.delenv("RIVALFORGE_FEATURE_TELEGRAM_BOT", raising=False)
        assert main(["telegram"]) == 1
        assert "RIVALFORGE_FEATURE_TELEGRAM_BOT" in capsys.readouterr().err

    def test_a_missing_token_is_a_clear_error_not_a_traceback(self, capsys, monkeypatch):
        monkeypatch.setenv("RIVALFORGE_FEATURE_TELEGRAM_BOT", "1")
        monkeypatch.delenv("RIVALFORGE_TELEGRAM_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        assert main(["telegram"]) == 2
        assert "RIVALFORGE_TELEGRAM_TOKEN" in capsys.readouterr().err

    def test_a_malformed_token_fails_before_a_single_request(self, capsys, monkeypatch):
        monkeypatch.setenv("RIVALFORGE_FEATURE_TELEGRAM_BOT", "1")
        monkeypatch.setenv("RIVALFORGE_TELEGRAM_TOKEN", "not-a-token")
        assert main(["telegram"]) == 2

    def test_the_token_is_not_a_command_line_argument(self):
        """Arguments are visible in `ps` and in shell history."""
        from rivalforge.cli.main import build_parser

        help_text = build_parser().format_help()
        for action in build_parser()._subparsers._group_actions[0].choices["telegram"]._actions:
            assert "token" not in " ".join(action.option_strings)
        assert "--token" not in help_text
