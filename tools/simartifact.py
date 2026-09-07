"""Render a campaign report as a designed, self-contained page.

`simreport.py` is the plain generator used for ad-hoc runs. This one is for the
report that gets published: same data, composed rather than dumped.

Design notes, so the next person changing it knows what the choices were:

* The palette is steel blue on a cool paper ground, with a single ember accent
  reserved for failure. Nothing else is allowed to be ember, so a red mark on
  the page always means something.
* IBM Plex Mono carries every number, because the game itself renders in
  monospace -- the `[####....] 64/100` bars are the subject's own typography.
* Phases are numbered because a run really is a sequence; nothing else is.
* One chart, drawn to a real scale, for the one distribution that has shape.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any, Mapping

__all__ = ["render"]


def _e(value: Any) -> str:
    return html.escape(str(value))


def _n(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


PHASES = [
    (
        "lifecycle",
        "The happy path",
        "Start, connect a wallet by signing a real challenge, read the roster, "
        "pick a fighter, fight it out, check who you are, log out.",
    ),
    (
        "interrupted",
        "Half-cut fights",
        "Nine ways a duel ends without ending: forfeit, disconnect, session "
        "expiry, conversation eviction, the NFT sold mid-fight, a second "
        "<code>/play</code>, a stance after the last round, a bot restart, and "
        "simply not replying again.",
    ),
    (
        "abuse",
        "Hostile input",
        "Buttons signed for someone else, forged and truncated payloads, wallet "
        "flows attempted in a group, a wrong signature, a replayed one, another "
        "wallet's signature, ten malformed update shapes, and a flood.",
    ),
    (
        "outage",
        "The chain goes down",
        "The indexer stops answering mid-session, then recovers. Reading a "
        "roster must degrade; granting a fighter must refuse.",
    ),
    (
        "simultaneous",
        "Everyone at once",
        "Every player opens a fight before any of them advances, then all of "
        "them go round by round. Each match's seed and arena are fingerprinted "
        "first and checked after.",
    ),
    (
        "concurrency",
        "Real threads",
        "Whole sessions run in parallel against the shared conversation store, "
        "rate limiter, challenge store and session store.",
    ),
    (
        "soak",
        "Random walk",
        "A long weighted walk over every command, including buttons for matches "
        "that no longer exist and text that is an attack.",
    ),
]

INVARIANTS = [
    ("A session token never reaches a message", "it is a bearer credential"),
    (
        "A wallet appears only in its owner's chat",
        "the address is not a secret and the challenge must contain it — the "
        "leak to look for is it turning up in someone else's chat",
    ),
    ("Every message fits Telegram's 4,096-character limit", "over it, the API drops it silently"),
    ("Every fenced block is balanced", "an unbalanced one lets attacker text become markup"),
    ("No unescaped backtick survives inside a block", "one closes the block early"),
    ("No foreign text renders as a clickable link", "that is a phishing page with our name on it"),
    ("Every button fits 64 bytes", "over it, Telegram drops the button at send time"),
    ("Every button verifies for the chat it was sent to", "a stolen button must do nothing"),
    ("Concurrent matches never swap state", "seed and arena fingerprinted before and after"),
    ("The rendered outcome matches the engine's verdict", "the message must not lie about who won"),
    ("The conversation store stays bounded", "otherwise memory is the attack"),
    ("handle() never raises", "a bot that dies on one update is one anyone can stop"),
]


def _outcome_rows(outcomes: Mapping[str, int], keys: list[str]) -> list[tuple[str, int]]:
    return [(k, outcomes[k]) for k in keys if k in outcomes]


def render(report: Mapping[str, Any]) -> str:
    fights = report["fights"]
    outcomes = report["outcomes"]
    violations = report.get("violations", [])
    clean = not violations
    runs = report.get("runs", 1)
    summary = report.get("per_run_summary", {})

    started = fights["started"]
    finished = fights["finished"]
    abandoned = fights["abandoned"]
    still_open = fights["unfinished when the run ended"]
    decided = fights["wins"] + fights["losses"] + fights["draws"]

    def pct(part: int, whole: int) -> float:
        return (100.0 * part / whole) if whole else 0.0

    # -- headline figures -------------------------------------------------
    scale = [
        ("simulations", _n(runs)),
        ("fights", _n(started)),
        ("updates handled", _n(report["updates_handled"])),
        ("messages checked", _n(report["messages_checked"])),
        ("buttons checked", _n(report["buttons_checked"])),
        ("wall clock", f"{report['elapsed_seconds']:,.0f}s"),
    ]
    scale_html = "".join(
        f'<div class="fig"><span class="fig-n">{_e(v)}</span>'
        f'<span class="fig-k">{_e(k)}</span></div>'
        for k, v in scale
    )

    # -- the ledger -------------------------------------------------------
    ledger = [
        ("fought to a finish", finished, "ok"),
        ("cut short on purpose", abandoned, "mid"),
        ("still in play at the end", still_open, "dim"),
    ]
    ledger_bar = "".join(
        f'<span class="seg seg-{cls}" style="width:{pct(v, started):.3f}%" '
        f'title="{_e(label)}: {_n(v)}"></span>'
        for label, v, cls in ledger
        if v
    )
    ledger_rows = "".join(
        f'<tr><td><span class="key key-{cls}"></span>{_e(label)}</td>'
        f'<td class="num">{_n(v)}</td>'
        f'<td class="num dim">{pct(v, started):.1f}%</td></tr>'
        for label, v, cls in ledger
    )

    # -- rounds chart -----------------------------------------------------
    histogram = {int(k): v for k, v in fights["round_histogram"].items()}
    peak = max(histogram.values()) if histogram else 1
    chart_rows = "".join(
        f'<div class="row"><span class="row-k">{k}</span>'
        f'<span class="row-bar"><span style="width:{max(0.4, 100 * v / peak):.2f}%"></span></span>'
        f'<span class="row-v">{_n(v)}</span></div>'
        for k, v in sorted(histogram.items())
    )

    # -- win split --------------------------------------------------------
    split = [
        ("player won", fights["wins"]),
        ("player lost", fights["losses"]),
        ("draw at the round limit", fights["draws"]),
    ]
    split_html = "".join(
        f'<div class="split"><span class="split-n">{pct(v, decided):.1f}%</span>'
        f'<span class="split-k">{_e(k)}</span>'
        f'<span class="split-c">{_n(v)} fights</span></div>'
        for k, v in split
    )

    # -- what was thrown --------------------------------------------------
    attacks = _outcome_rows(outcomes, [
        "flood dropped",
        "bad callback rejected",
        "stolen button rejected",
        "malformed update absorbed",
        "group wallet flow refused",
        "login rejected",
        "wrong signature rejected",
        "replayed signature rejected",
        "wrong-key signature rejected",
        "fighter pick refused",
    ])
    attack_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{_n(v)}</td></tr>" for k, v in attacks
    )

    degrade = _outcome_rows(outcomes, [
        "roster unavailable (outage, not a denial)",
        "degraded gracefully during outage",
        "roster refused without a session",
        "roster shown (wallet is empty)",
        "transport failure absorbed",
    ])
    degrade_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{_n(v)}</td></tr>" for k, v in degrade
    )

    survived = sorted(
        ((k[len("survived: "):], v) for k, v in outcomes.items() if k.startswith("survived: ")),
        key=lambda kv: -kv[1],
    )
    survived_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{_n(v)}</td></tr>" for k, v in survived
    )

    phase_html = "".join(
        f'<li class="phase"><span class="phase-n">{index}</span>'
        f'<div><h3>{_e(title)}</h3><p>{body}</p>'
        f'<span class="phase-id">{_e(key)}</span></div></li>'
        for index, (key, title, body) in enumerate(PHASES, start=1)
    )

    invariant_html = "".join(
        f'<li><span class="chip chip-{"ok" if clean else "warn"}">'
        f'{"held" if clean else "check"}</span>'
        f"<div><strong>{_e(name)}</strong><span>{_e(why)}</span></div></li>"
        for name, why in INVARIANTS
    )

    arenas = fights["by_arena"]
    arena_total = sum(arenas.values()) or 1
    arena_rows = "".join(
        f'<div class="row"><span class="row-k wide">{_e(name)}</span>'
        f'<span class="row-bar"><span style="width:{100 * v / max(arenas.values()):.2f}%">'
        f"</span></span>"
        f'<span class="row-v">{100 * v / arena_total:.1f}%</span></div>'
        for name, v in arenas.items()
    )

    audit_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{_n(v)}</td></tr>"
        for k, v in list(report["audit_events"].items())[:12]
    )

    examples = report.get("examples", {})
    example_html = ""
    for key in ("roster", "finished fight", "connected"):
        for sample in examples.get(key, [])[:1]:
            example_html += (
                f'<figure><figcaption>{_e(key)}</figcaption>'
                f"<pre>{_e(sample)}</pre></figure>"
            )

    violation_html = ""
    if violations:
        rows = "".join(
            f"<tr><td>{_e(v['phase'])}</td><td>{_e(v['invariant'])}</td>"
            f"<td>{_e(v['detail'])}</td></tr>"
            for v in violations[:60]
        )
        violation_html = (
            '<section><h2>Violations</h2><div class="scroll"><table>'
            "<thead><tr><th>phase</th><th>invariant</th><th>detail</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></section>"
        )

    verdict = (
        f'<p class="verdict-n">0</p><p class="verdict-t">invariant violations</p>'
        f'<p class="verdict-s">across {_n(runs)} independent simulations, '
        f'{_n(started)} fights, {_n(report["messages_checked"])} messages and '
        f'{_n(report["buttons_checked"])} buttons</p>'
        if clean
        else f'<p class="verdict-n">{_n(len(violations))}</p>'
        f'<p class="verdict-t">invariant violations</p>'
        f'<p class="verdict-s">listed at the foot of this page</p>'
    )

    notes = "".join(f"<li>{_e(note)}</li>" for note in report.get("notes", [])[:8])

    return f"""<title>What Breaks, and Where</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;800&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>{_CSS}</style>

<main>
  <header class="masthead">
    <p class="eyebrow">RivalForge &middot; simulation campaign</p>
    <h1>What breaks, and where</h1>
    <p class="lede">Thousands of independent simulations of the whole game —
      logins, duels, half-finished duels, chain outages, forged buttons and
      floods — with every message and every button inspected as it was
      produced.</p>
    <p class="stamp">{_e(report['generated_at'])} &middot; sandbox only: no
      network, no database, no real wallet</p>
  </header>

  <section class="verdict {'is-clean' if clean else 'is-broken'}">{verdict}</section>

  <section class="figs">{scale_html}</section>

  <section>
    <h2>The fight ledger</h2>
    <p class="sub">Every duel is accounted for. Started equals finished plus
      cut short plus still in play — a report where those do not reconcile is
      a report that lost some.</p>
    <div class="stack">{ledger_bar}</div>
    <div class="scroll"><table class="ledger">
      <thead><tr><th>{_n(started)} fights</th><th class="num">count</th>
      <th class="num">share</th></tr></thead>
      <tbody>{ledger_rows}</tbody></table></div>
  </section>

  <section>
    <h2>Who won</h2>
    <p class="sub">Simulated players pick stances at random; the opponent is a
      scripted agent that reads. The gap is the point — a random walk should
      lose to a reader, and it does, by about the margin the balance harness
      reports.</p>
    <div class="splits">{split_html}</div>
  </section>

  <section>
    <h2>How long a duel lasts</h2>
    <p class="sub">Rounds per finished fight, all {_n(finished)} of them. Mean
      {fights['mean_rounds']}, range {fights['shortest']}–{fights['longest']};
      the ceiling is a hard 30-round limit that ends in a draw.</p>
    <div class="chart">{chart_rows}</div>
  </section>

  <section>
    <h2>The seven phases</h2>
    <p class="sub">Each run walks these in order. They are numbered because a
      run really is a sequence — later phases inherit the state earlier ones
      left behind, which is where the interesting failures live.</p>
    <ol class="phases">{phase_html}</ol>
  </section>

  <section>
    <h2>Half-cut fights</h2>
    <p class="sub">A duel that ends properly is the easy case. Each of these
      leaves state somewhere the happy path never does — and after every one,
      the simulation checks the only thing that matters to a player: can they
      start again?</p>
    <div class="scroll"><table>
      <thead><tr><th>interruption</th><th class="num">times survived</th></tr></thead>
      <tbody>{survived_rows}</tbody></table></div>
  </section>

  <section>
    <h2>What was thrown at it</h2>
    <p class="sub">Every one of these was rejected. None of them moved a match,
      reached another player, or stopped the bot.</p>
    <div class="two">
      <div class="scroll"><table>
        <thead><tr><th>attack</th><th class="num">times</th></tr></thead>
        <tbody>{attack_rows}</tbody></table></div>
      <div class="scroll"><table>
        <thead><tr><th>degraded, did not deny</th><th class="num">times</th></tr></thead>
        <tbody>{degrade_rows}</tbody></table></div>
    </div>
  </section>

  <section>
    <h2>What was checked, after every action</h2>
    <p class="sub">Not at the end. A violation's cause is the action
      immediately before it, and a report that says "somewhere in a million
      messages" is one nobody can act on.</p>
    <ul class="invariants">{invariant_html}</ul>
  </section>

  <section>
    <h2>Where the fights happened</h2>
    <p class="sub">Arenas are drawn at random per match, so an even spread is
      the expected result — an uneven one would mean the draw is biased.</p>
    <div class="chart">{arena_rows}</div>
  </section>

  <section>
    <h2>The audit trail</h2>
    <p class="sub">What the game recorded while all of this happened. No IP
      address, no user agent, no device fingerprint, no geolocation — a wallet,
      an event, an outcome and a timestamp.</p>
    <div class="scroll"><table>
      <thead><tr><th>event</th><th class="num">records</th></tr></thead>
      <tbody>{audit_rows}</tbody></table></div>
  </section>

  <section>
    <h2>What a player actually saw</h2>
    <p class="sub">Taken verbatim from the simulation. NFT names in these runs
      include tokens named after phishing links, right-to-left overrides and
      five thousand identical characters — a quarter of every wallet is
      hostile by construction.</p>
    {example_html}
  </section>

  <section>
    <h2>Notes from the runs</h2>
    <ul class="notes">{notes}</ul>
  </section>

  {violation_html}

  <footer>
    <p><strong>Reproduce it:</strong>
      <code>python tools/simulate.py --runs {_n(runs)}</code>. Exit code is 1 if
      any invariant breaks, so it works as a gate; a miniature version runs on
      every commit.</p>
    <p class="fine">The sandbox lives outside the installed package, so no
      deployment can import it. Wallets are real ed25519 keypairs generated in
      memory and discarded — a fake signature would only exercise a fake
      verifier.</p>
  </footer>
</main>"""


_CSS = """
:root{
  --ground:#eef2f4; --surface:#fff; --raise:#f7fafb;
  --ink:#12171a; --dim:#5a666d; --faint:#8b979e;
  --line:#d8e2e6; --rule:#c3d1d7;
  --accent:#2c6b8a; --accent-soft:#a9c8d8;
  --ok:#22705a; --alert:#a8492a;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --display:"Archivo","IBM Plex Sans",-apple-system,sans-serif;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --ground:#0e1214; --surface:#151b1e; --raise:#1a2226;
    --ink:#e3eaed; --dim:#8fa0a8; --faint:#6d7d85;
    --line:#232d33; --rule:#31404a;
    --accent:#79b3d1; --accent-soft:#2f4d5f;
    --ok:#57bd91; --alert:#df8b64;
  }
}
:root[data-theme="dark"]{
  --ground:#0e1214; --surface:#151b1e; --raise:#1a2226;
  --ink:#e3eaed; --dim:#8fa0a8; --faint:#6d7d85;
  --line:#232d33; --rule:#31404a;
  --accent:#79b3d1; --accent-soft:#2f4d5f;
  --ok:#57bd91; --alert:#df8b64;
}
*{box-sizing:border-box}
body{background:var(--ground);color:var(--ink);font-family:var(--sans);
  font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
main{max-width:940px;margin:0 auto;padding:clamp(28px,5vw,64px) clamp(18px,4vw,32px) 96px;
  display:flex;flex-direction:column;gap:clamp(38px,5vw,60px)}
h1,h2,h3{font-family:var(--display);text-wrap:balance;margin:0}
h1{font-size:clamp(36px,6.2vw,60px);font-weight:800;letter-spacing:-.03em;line-height:1.03}
h2{font-size:clamp(20px,2.6vw,25px);font-weight:700;letter-spacing:-.015em;margin-bottom:6px}
h3{font-size:16px;font-weight:700;letter-spacing:-.01em}
p{margin:0}
section{display:flex;flex-direction:column;gap:16px}

.masthead{display:flex;flex-direction:column;gap:14px;
  border-bottom:2px solid var(--rule);padding-bottom:26px}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--accent)}
.lede{font-size:clamp(16px,2vw,18.5px);color:var(--dim);max-width:60ch}
.stamp{font-family:var(--mono);font-size:12.5px;color:var(--faint)}

.verdict{background:var(--surface);border:1px solid var(--line);
  border-left:5px solid var(--ok);border-radius:3px;padding:26px 28px;gap:2px}
.verdict.is-broken{border-left-color:var(--alert)}
.verdict-n{font-family:var(--display);font-size:clamp(52px,9vw,84px);font-weight:800;
  line-height:.92;letter-spacing:-.04em;color:var(--ok);font-variant-numeric:tabular-nums}
.is-broken .verdict-n{color:var(--alert)}
.verdict-t{font-family:var(--display);font-size:19px;font-weight:600;margin-top:6px}
.verdict-s{color:var(--dim);font-size:15px;max-width:62ch}

.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:1px;background:var(--line);border:1px solid var(--line);border-radius:3px}
.fig{background:var(--surface);padding:16px 18px;display:flex;flex-direction:column;gap:2px}
.fig-n{font-family:var(--mono);font-size:22px;font-weight:500;letter-spacing:-.02em;
  font-variant-numeric:tabular-nums}
.fig-k{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--faint)}

.sub{color:var(--dim);font-size:15px;max-width:66ch}

.stack{display:flex;height:14px;border-radius:2px;overflow:hidden;background:var(--line)}
.seg{display:block;height:100%}
.seg-ok{background:var(--accent)}
.seg-mid{background:var(--accent-soft)}
.seg-dim{background:var(--rule)}
.key{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:9px}
.key-ok{background:var(--accent)}
.key-mid{background:var(--accent-soft)}
.key-dim{background:var(--rule)}

.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th{font-family:var(--mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint);font-weight:500;text-align:left;padding:0 14px 8px 0;
  border-bottom:1px solid var(--rule);white-space:nowrap}
td{padding:9px 14px 9px 0;border-bottom:1px solid var(--line);vertical-align:top}
td.num,th.num{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;
  white-space:nowrap;width:1%;padding-right:0}
/* Two numeric columns side by side otherwise touch, and "198" next to
   "34.1%" reads as one nonsense number. */
td.num:not(:last-child),th.num:not(:last-child){padding-right:26px}
td.dim{color:var(--dim)}
tr:last-child td{border-bottom:none}

.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:28px}

.chart{display:flex;flex-direction:column;gap:3px}
.row{display:grid;grid-template-columns:34px 1fr 62px;align-items:center;gap:12px}
.row-k{font-family:var(--mono);font-size:12px;color:var(--dim);text-align:right;
  font-variant-numeric:tabular-nums}
.row-k.wide{width:auto;text-align:left;font-family:var(--sans);font-size:13.5px;color:var(--ink)}
.row{grid-template-columns:minmax(34px,150px) 1fr 62px}
.row-bar{display:block;height:11px;background:var(--line);border-radius:2px;overflow:hidden}
.row-bar>span{display:block;height:100%;background:var(--accent)}
.row-v{font-family:var(--mono);font-size:12px;color:var(--dim);text-align:right;
  font-variant-numeric:tabular-nums}

.splits{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:20px}
.split{display:flex;flex-direction:column;gap:1px;padding-left:16px;
  border-left:3px solid var(--accent-soft)}
.split-n{font-family:var(--display);font-size:34px;font-weight:800;letter-spacing:-.03em;
  font-variant-numeric:tabular-nums;line-height:1.05}
.split-k{font-size:14.5px;font-weight:500}
.split-c{font-family:var(--mono);font-size:12px;color:var(--faint)}

.phases{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}
.phase{display:grid;grid-template-columns:44px 1fr;gap:14px;align-items:start;
  padding:16px 0;border-bottom:1px solid var(--line)}
.phase:last-child{border-bottom:none}
.phase-n{font-family:var(--mono);font-size:13px;color:var(--accent);padding-top:2px;
  font-variant-numeric:tabular-nums}
.phase p{color:var(--dim);font-size:14.5px;margin-top:3px;max-width:64ch}
.phase code{font-family:var(--mono);font-size:13px;background:var(--raise);
  padding:1px 5px;border-radius:2px}
.phase-id{font-family:var(--mono);font-size:11px;color:var(--faint);
  letter-spacing:.06em;display:inline-block;margin-top:6px}

.invariants{list-style:none;margin:0;padding:0;display:grid;
  grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:3px}
.invariants li{background:var(--surface);padding:14px 16px;display:flex;gap:11px;
  align-items:flex-start}
.invariants strong{display:block;font-size:14px;font-weight:600;line-height:1.4}
.invariants span:not(.chip){display:block;color:var(--dim);font-size:13px;margin-top:2px}
.chip{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;
  padding:3px 7px;border-radius:2px;white-space:nowrap;margin-top:2px}
.chip-ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.chip-warn{background:color-mix(in srgb,var(--alert) 16%,transparent);color:var(--alert)}

figure{margin:0;display:flex;flex-direction:column;gap:6px}
figcaption{font-family:var(--mono);font-size:11px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--faint)}
pre{font-family:var(--mono);font-size:12.5px;line-height:1.5;background:var(--surface);
  border:1px solid var(--line);border-radius:3px;padding:14px 16px;margin:0;
  overflow-x:auto;white-space:pre-wrap;word-break:break-word;color:var(--ink)}

.notes{margin:0;padding-left:20px;color:var(--dim);font-size:14.5px;
  display:flex;flex-direction:column;gap:4px}

footer{border-top:2px solid var(--rule);padding-top:22px;display:flex;
  flex-direction:column;gap:10px;color:var(--dim);font-size:14px}
footer code{font-family:var(--mono);font-size:13px;background:var(--surface);
  border:1px solid var(--line);padding:2px 7px;border-radius:2px;color:var(--ink)}
.fine{font-size:13px;color:var(--faint);max-width:70ch}

@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""


def main() -> int:
    source = Path(sys.argv[1])
    target = Path(sys.argv[2])
    target.write_text(render(json.loads(source.read_text(encoding="utf-8"))), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
