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
