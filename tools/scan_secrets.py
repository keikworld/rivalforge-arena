#!/usr/bin/env python3
"""Refuse to let a secret reach the repository.

Runs in CI on every push and can be run by hand::

    python tools/scan_secrets.py

Two things make a scanner like this useful rather than noise:

* **It is allowed to be wrong in one direction only.** A false positive costs a
  minute; a false negative costs a key. So the patterns are broad.
* **Fixtures are marked, not excepted by path.** Test files that deliberately
  contain secret-shaped strings assemble them at runtime and carry a
  NOT-A-REAL-SECRET comment. Excluding `tests/` wholesale would have been
  easier and would also have stopped the scanner ever protecting those files.
"""
import re, sys, pathlib, subprocess

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".hypothesis", "build", "dist", ".venv"}

PATTERNS = [
    ("private key block",   re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT",                 re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("AWS access key",      re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token",        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("Slack token",         re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe key",          re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}")),
    ("OpenAI key",          re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("Helius/UUID key",     re.compile(r"api[-_]?key\s*[:=]\s*[\"'][A-Za-z0-9\-]{16,}[\"']", re.I)),
    ("generic secret assign", re.compile(
        r"(?i)\b(password|passwd|secret|token|api_key|apikey|private_key)\s*[:=]\s*[\"'][^\"']{8,}[\"']")),
    ("hex seed (64 chars)", re.compile(r"\"seed\"\s*:\s*\"[0-9a-f]{64}\"")),
    # A Telegram bot token. Whoever holds one *is* the bot: they can read
    # every message sent to it and post as it. There is no leading word
    # boundary because the token appears in a URL as `/bot<token>`.
    ("Telegram bot token",  re.compile(r"(?<!\d)\d{6,12}:[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")),
    ("postgres URL",        re.compile(r"postgres(ql)?://[^\s\"']*:[^\s\"'@]+@")),
    ("connection w/ pwd",   re.compile(r"(?i)(mongodb|mysql|redis)://[^\s\"']*:[^\s\"'@]+@")),
]

# Values that are legitimately present and are NOT secrets.
#: Fixtures are exempted by an in-line marker, never by value.
#:
#: An earlier version allowlisted the fixture *strings* -- "hunter2" and the
#: like. That was a real hole: any file anywhere in the tree containing one of
#: those substrings was skipped, so a genuine credential that happened to sit
#: on a line with a fixture value would have passed. It was caught by a test
#: that planted a real-looking DSN using "hunter2" as the password and saw the
#: scanner stay silent.
#:
#: A marker is scoped to the line it is on (or the line above), so exempting
#: one fixture cannot accidentally exempt anything else.
MARKER = "NOT-A-REAL-SECRET"

#: A credential made of variable references is not a credential. `${VAR}`,
#: `$(cmd)`, `{{ secrets.X }}`, `%(name)s` and `<placeholder>` are all
#: indirection, and flagging them trains people to ignore the scanner -- which
#: is how a real finding gets waved through.
INDIRECTION = re.compile(r"\$\{|\$\(|\{\{|%\(|%s\b|<[A-Za-z_]+>")


def _is_indirection(snippet: str) -> bool:
    return bool(INDIRECTION.search(snippet))


findings = []
for path in sorted(ROOT.rglob("*")):
    if not path.is_file():
        continue
    if any(part in SKIP_DIRS for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    lines = text.splitlines()
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(0)
            if _is_indirection(snippet):
                continue
            number = text[: match.start()].count("\n") + 1
            # The marker must be on this line or the one above it.
            context = " ".join(lines[max(0, number - 2) : number])
            if MARKER in context:
                continue
            findings.append((str(path.relative_to(ROOT)), number, label, snippet[:70]))

print(f"scanned {ROOT}")
if findings:
    print(f"\n!! {len(findings)} POTENTIAL SECRET(S):\n")
    for f in findings:
        print(f"  {f[0]}:{f[1]}  [{f[2]}]  {f[3]}")
    sys.exit(1)
print("no secrets found")
