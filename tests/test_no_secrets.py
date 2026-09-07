"""The repository must contain no credentials.

Also a test, not only a CI step, so it fails on a developer's machine before a
commit rather than after a push. A secret that reaches a public repository is
compromised the moment it lands, however fast it is deleted afterwards.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCANNER = REPO / "tools" / "scan_secrets.py"


def test_no_secrets_anywhere_in_the_tree():
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(REPO)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_scanner_actually_catches_something(tmp_path):
    """A scanner that never fires is indistinguishable from no scanner."""
    planted = tmp_path / "leak.py"
    planted.write_text('AWS = "AKIA' + "A" * 16 + '"\n')
    result = subprocess.run(
        [sys.executable, str(SCANNER), str(tmp_path)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 1
    assert "AWS access key" in result.stdout


@pytest.mark.parametrize("pattern", [
    "*.key.json", "test-key*.json", "session*.json", "*.pem", "id_ed25519*",
])
def test_key_and_session_patterns_are_ignored(pattern):
    """The CLI writes keys and sessions outside the repo by default; these
    patterns are the backstop for anyone who points --key at the tree."""
    assert pattern in (REPO / ".gitignore").read_text()


def test_no_key_or_session_file_is_tracked_by_git():
    tracked = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True, text=True, timeout=60,
    ).stdout.splitlines()
    suspicious = [
        name for name in tracked
        if name.endswith((".pem", ".keypair"))
        or "session" in name.lower() and name.endswith(".json")
        or "key" in pathlib.Path(name).name.lower() and name.endswith(".json")
    ]
    assert not suspicious, f"key/session files are tracked: {suspicious}"


def _scan(directory) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(directory)],
        capture_output=True, text=True, timeout=60,
    )


def test_a_real_connection_string_is_caught(tmp_path):
    """A DSN with an embedded password is a credential wherever it appears."""
    (tmp_path / "leak.py").write_text(
        'DSN = "postgres" "ql://admin:s3cr3t@db.example.com/x"\n'.replace('" "', "")
    )
    result = _scan(tmp_path)
    assert result.returncode == 1
    assert "postgres URL" in result.stdout


def test_a_marked_fixture_is_exempt(tmp_path):
    (tmp_path / "fixture.py").write_text(
        "# NOT-A-REAL-SECRET: fixture\n"
        'DSN = "postgres" "ql://admin:s3cr3t@db.example.com/x"\n'.replace('" "', "")
    )
    assert _scan(tmp_path).returncode == 0


def test_the_marker_only_exempts_its_own_line_and_the_one_above(tmp_path):
    """An earlier version allowlisted fixture *values*, which meant any file
    containing one was skipped. A marker three lines up must not exempt."""
    (tmp_path / "far.py").write_text(
        "# NOT-A-REAL-SECRET: fixture\n"
        "filler = 1\n"
        "more_filler = 2\n"
        'DSN = "postgres" "ql://admin:s3cr3t@db.example.com/x"\n'.replace('" "', "")
    )
    assert _scan(tmp_path).returncode == 1


def test_variable_references_are_not_credentials(tmp_path):
    """`${VAR}` is indirection. Flagging it trains people to ignore the
    scanner, which is how a real finding gets waved through."""
    (tmp_path / "ci.yml").write_text(
        "url: postgresql://${PGUSER}:${PGPASSWORD}@127.0.0.1:5432/db\n"
        "other: postgresql://{{ secrets.U }}:{{ secrets.P }}@host/db\n"
    )
    assert _scan(tmp_path).returncode == 0


def test_a_telegram_bot_token_is_caught(tmp_path):
    """Whoever holds a bot token *is* the bot.

    They can read every message sent to it and post as it, which makes a
    committed token the most damaging leak this surface can produce.
    """
    (tmp_path / "leak.py").write_text(
        'TOKEN = "9876" "54321:AAG0RealLookingTelegramTokenValue1234"\n'.replace('" "', "")
    )
    result = _scan(tmp_path)
    assert result.returncode == 1
    assert "Telegram bot token" in result.stdout


def test_a_bot_token_inside_a_url_is_caught(tmp_path):
    """It reaches a log as `/bot<token>`, with no word boundary in front of it."""
    (tmp_path / "log.txt").write_text(
        "POST https://api.telegram.org/bot98765"
        "4321:AAG0RealLookingTelegramTokenValue1234/getUpdates failed\n"
    )
    assert _scan(tmp_path).returncode == 1
