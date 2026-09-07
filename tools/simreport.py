"""Render a simulation report as a single self-contained HTML page.

No CDN, no fonts, no scripts fetched from anywhere: the page is the file. A
report that needs the network to render is a report that stops rendering.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Mapping

__all__ = ["write_html"]

_CSS = """
:root{--bg:#faf9f7;--fg:#1c1b19;--dim:#6b6862;--line:#e2ded8;--card:#fff;
--ok:#1f7a4d;--bad:#b3261e;--warn:#8a6d1f;--accent:#33566e;}
@media (prefers-color-scheme:dark){:root{--bg:#16181a;--fg:#e8e6e3;--dim:#9a958d;
--line:#2c2f33;--card:#1d2023;--ok:#59c08b;--bad:#f2837a;--warn:#d9b45a;--accent:#8fb6d1;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:28px;margin:0 0 4px;letter-spacing:-.02em}
h2{font-size:19px;margin:38px 0 12px;letter-spacing:-.01em}
h3{font-size:15px;margin:22px 0 8px;color:var(--dim);text-transform:uppercase;
letter-spacing:.08em;font-weight:600}
.sub{color:var(--dim);margin:0 0 24px}
.banner{padding:14px 18px;border-radius:10px;font-weight:600;margin:0 0 28px}
.banner.ok{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok);
border:1px solid color-mix(in srgb,var(--ok) 35%,transparent)}
.banner.bad{background:color-mix(in srgb,var(--bad) 14%,transparent);color:var(--bad);
border:1px solid color-mix(in srgb,var(--bad) 35%,transparent)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:24px;font-weight:650;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.card .k{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em;
margin-top:2px}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:7px 12px 7px 0;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.06em}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;
padding-right:18px;width:1%}
.bar{display:block;height:7px;border-radius:4px;background:var(--accent);min-width:2px}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;
overflow-x:auto;font-size:12.5px;line-height:1.45;margin:8px 0 0}
.note{color:var(--dim);font-size:14px;margin:4px 0}
footer{margin-top:56px;padding-top:18px;border-top:1px solid var(--line);
color:var(--dim);font-size:13px}
"""


def _e(value: Any) -> str:
    return html.escape(str(value))


def _cards(pairs) -> str:
    cells = "".join(
        f'<div class="card"><div class="n">{_e(v)}</div><div class="k">{_e(k)}</div></div>'
        for k, v in pairs
    )
    return f'<div class="grid">{cells}</div>'


def _table(rows: Mapping[str, Any], head=("what", "count"), bars: bool = True) -> str:
    if not rows:
        return '<p class="note">nothing recorded</p>'
    peak = max((v for v in rows.values() if isinstance(v, (int, float))), default=0) or 1
    body = []
    for key, value in rows.items():
        bar = ""
        if bars and isinstance(value, (int, float)):
            width = max(2, round(100 * value / peak))
            bar = f'<span class="bar" style="width:{width}%"></span>'
        body.append(
            f"<tr><td>{_e(key)}</td><td class='n'>{value:,}</td><td>{bar}</td></tr>"
            if isinstance(value, int)
            else f"<tr><td>{_e(key)}</td><td class='n'>{_e(value)}</td><td>{bar}</td></tr>"
        )
    return (
        f'<div class="scroll"><table><thead><tr><th>{_e(head[0])}</th>'
        f'<th class="n">{_e(head[1])}</th><th></th></tr></thead>'
        f"<tbody>{''.join(body)}</tbody></table></div>"
    )


def write_html(report: Mapping[str, Any], path: Path) -> None:
    fights = report["fights"]
    violations = report.get("violations", [])
    clean = not violations

    banner = (
        '<div class="banner ok">No invariant violations. Every message, button, '
        "login, fight and interruption below behaved as specified.</div>"
        if clean
        else f'<div class="banner bad">{len(violations)} invariant violation(s). '
        "Details at the bottom.</div>"
    )

    runs = report.get("runs")
    headline = [
        ("simulation runs", f"{runs:,}") if runs else ("players", f"{report['players']:,}"),
        ("updates handled", f"{report['updates_handled']:,}"),
        ("fights started", f"{fights['started']:,}"),
        ("fights finished", f"{fights['finished']:,}"),
        ("messages checked", f"{report['messages_checked']:,}"),
        ("buttons checked", f"{report['buttons_checked']:,}"),
        ("elapsed", f"{report['elapsed_seconds']}s"),
    ]

    outcome_rows = ""
    total_decided = fights["wins"] + fights["losses"] + fights["draws"]
    if total_decided:
        outcome_rows = _table(
            {
                "player won": fights["wins"],
                "player lost": fights["losses"],
                "draw at the round limit": fights["draws"],
                "abandoned mid-fight": fights["abandoned"],
            }
        )

    violation_block = ""
    if violations:
        rows = "".join(
            f"<tr><td>{_e(v['phase'])}</td><td>{_e(v['invariant'])}</td>"
            f"<td>{_e(v['action'])}</td><td>{_e(v['detail'])}</td></tr>"
            for v in violations[:200]
        )
        violation_block = (
            "<h2>Violations</h2><div class='scroll'><table><thead><tr><th>phase</th>"
            "<th>invariant</th><th>during</th><th>detail</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )

    examples = ""
    for key, values in (report.get("examples") or {}).items():
        shown = "".join(f"<pre>{_e(v)}</pre>" for v in values[:2])
        examples += f"<h3>{_e(key)}</h3>{shown}"

    notes = "".join(f'<p class="note">{_e(n)}</p>' for n in report.get("notes", []))

    per_run = ""
    if report.get("per_run_summary"):
        per_run = "<h2>Across runs</h2>" + _table(
            report["per_run_summary"], head=("measure", "value"), bars=False
        )

    doc = f"""<title>RivalForge Simulation Report</title>
<style>{_CSS}</style>
<div class="wrap">
<h1>RivalForge simulation report</h1>
<p class="sub">{_e(report['generated_at'])} &middot; sandbox only: no network,
no database, no real wallet.</p>
{banner}
{_cards(headline)}

<h2>Fights</h2>
{_cards([
    ("started", f"{fights['started']:,}"),
    ("finished", f"{fights['finished']:,}"),
    ("abandoned", f"{fights['abandoned']:,}"),
    ("mean rounds", fights["mean_rounds"]),
    ("shortest", fights["shortest"]),
    ("longest", fights["longest"]),
])}
{outcome_rows}

<h3>Rounds per fight</h3>
{_table({f"{k} rounds": v for k, v in fights['round_histogram'].items()},
        head=("length", "fights"))}

<h3>By arena</h3>
{_table(fights['by_arena'], head=("arena", "fights"))}

<h2>What happened</h2>
{_table(report['outcomes'], head=("outcome", "times"))}

<h2>What was sent</h2>
{_table(report['actions'], head=("action", "times"))}

<h2>The chain</h2>
{_table(report['chain'], head=("call", "count"))}

<h2>Audit trail</h2>
{_table(report['audit_events'], head=("event", "records"))}

{per_run}

<h2>Errors</h2>
{_table(report['errors'], head=("error", "times"))}

<h2>Notes</h2>
{notes or '<p class="note">none</p>'}

<h2>Examples</h2>
{examples or '<p class="note">none captured</p>'}

{violation_block}

<footer>Generated by <code>tools/simulate.py</code>. The sandbox lives outside the
installed package so no deployment can import it.</footer>
</div>"""
    path.write_text(doc, encoding="utf-8")
