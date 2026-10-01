"""Run reports: every trial's trace and verdict, as JSON and a static HTML page.

The terminal output summarises; the report keeps the evidence. Each record is
one trial — which scenario and attack, which target, the injected payload, the
recorded tool calls, and the findings pointing at the violating spans — so any
cell of a violation table can be traced back to exactly what the agent did.

`report.html` is a single self-contained file (inline CSS, no JavaScript, no
network), so it can be opened locally, attached to a ticket, or committed.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import Any

from . import __version__
from .scenario import Scenario


@dataclass
class Report:
    command: str = field(default_factory=lambda: " ".join(["agentred", *sys.argv[1:]]))
    generated_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%d %H:%M:%S %Z"))
    records: list[dict[str, Any]] = field(default_factory=list)
    audits: list[dict[str, Any]] = field(default_factory=list)

    def add_audit(self, server: str, command: list[str], tools: list[dict[str, Any]], findings: list[Any]) -> None:
        """Record a third-party server's tool metadata and its heuristic audit."""
        self.audits.append(
            {
                "server": server,
                "command": command,
                "tools": [{"name": t["name"], "description": t.get("description", "")} for t in tools],
                "findings": [
                    {"tool": f.tool, "location": f.location, "indicator": f.indicator, "excerpt": f.excerpt}
                    for f in findings
                ],
            }
        )

    def add(self, scenario: Scenario, summary: Any) -> None:
        """Record every trial in a TrialSummary run against `scenario`."""
        for trial, (run, verdict) in enumerate(zip(summary.runs, summary.verdicts), start=1):
            self.records.append(
                {
                    "scenario": scenario.id,
                    "category": scenario.category,
                    "invariant": scenario.invariant,
                    "attack": scenario.attack,
                    "injection_point": scenario.injection_point,
                    "target": summary.label,
                    "trial": trial,
                    "passed": verdict.passed,
                    "task": scenario.task,
                    "served_descriptions": {
                        t["name"]: t.get("description", "")
                        for t in run.trace.listed_tools
                        if scenario.server_command or t["name"] in scenario.description_overrides
                    },
                    "trace": [
                        {"span_id": c.span_id, "tool": c.name, "args": c.args, "result": c.result}
                        for c in run.trace.calls
                    ],
                    "findings": [
                        {"span_id": f.span_id, "invariant": f.invariant, "reason": f.reason}
                        for f in verdict.findings
                    ],
                    "final_text": run.final_text,
                }
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agentred_version": __version__,
            "command": self.command,
            "generated_at": self.generated_at,
            "records": self.records,
            "audits": self.audits,
        }

    def write(self, out_dir: str | Path) -> tuple[Path, Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        json_path, html_path = out / "report.json", out / "report.html"
        json_path.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        html_path.write_text(render_html(self.to_dict()), encoding="utf-8")
        return json_path, html_path


# ---------- HTML ----------

_CSS = """
:root {
  --bg: #fbfbfa; --fg: #1d1d1b; --muted: #6b6b66; --line: #e3e2de; --card: #ffffff;
  --fail: #b42318; --fail-bg: #fdecea; --pass: #1a7f37; --pass-bg: #e9f6ec;
  --warn-bg: #fff4e0; --code: #f4f3f0;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
  --bg: #161615; --fg: #ecebe7; --muted: #9b9a94; --line: #2e2d2a; --card: #1e1e1c;
  --fail: #ff8a80; --fail-bg: #3a1a17; --pass: #7ee2a0; --pass-bg: #15301e;
  --warn-bg: #3a2c12; --code: #262523; color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #161615; --fg: #ecebe7; --muted: #9b9a94; --line: #2e2d2a; --card: #1e1e1c;
  --fail: #ff8a80; --fail-bg: #3a1a17; --pass: #7ee2a0; --pass-bg: #15301e;
  --warn-bg: #3a2c12; --code: #262523; color-scheme: dark;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 24px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 40px 0 4px; }
h3 { font-size: 15px; margin: 24px 0 8px; }
.muted { color: var(--muted); }
code, pre { font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; }
pre { background: var(--code); padding: 10px 12px; border-radius: 6px; overflow-x: auto;
  white-space: pre-wrap; word-break: break-word; margin: 6px 0; }
.stats { display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }
.stat { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: 10px 14px; min-width: 120px; }
.stat b { display: block; font-size: 22px; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; background: var(--card);
  border: 1px solid var(--line); border-radius: 8px; }
th, td { padding: 7px 12px; text-align: left; border-bottom: 1px solid var(--line); }
th { font-weight: 600; font-size: 13px; color: var(--muted); }
td.cell { text-align: center; font-variant-numeric: tabular-nums; }
td.cell a { color: inherit; text-decoration: none; display: block; }
.r0 { background: var(--pass-bg); color: var(--pass); }
.rsome { background: var(--warn-bg); }
.rall { background: var(--fail-bg); color: var(--fail); font-weight: 600; }
details { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  margin: 8px 0; }
summary { cursor: pointer; padding: 8px 12px; }
details > div { padding: 0 12px 12px; }
.badge { display: inline-block; font-size: 12px; font-weight: 600; padding: 1px 8px;
  border-radius: 99px; margin-right: 6px; }
.badge.fail { background: var(--fail-bg); color: var(--fail); }
.badge.pass { background: var(--pass-bg); color: var(--pass); }
.span { border-left: 3px solid var(--line); padding: 2px 0 2px 10px; margin: 8px 0; }
.span.violation { border-left-color: var(--fail); }
.finding { color: var(--fail); font-weight: 600; }
"""


def _rate_class(viol: int, n: int) -> str:
    if viol == 0:
        return "r0"
    return "rall" if viol == n else "rsome"


def _anchor(*parts: str) -> str:
    return "g-" + "-".join("".join(ch if ch.isalnum() else "_" for ch in p) for p in parts)


def _trial_html(rec: dict[str, Any]) -> str:
    bad = {f["span_id"]: f for f in rec["findings"]}
    status = "fail" if not rec["passed"] else "pass"
    label = "FAIL" if not rec["passed"] else "PASS"
    out = [
        f'<details{" open" if not rec["passed"] else ""}><summary>'
        f'<span class="badge {status}">{label}</span>trial {rec["trial"]} '
        f'<span class="muted">· {len(rec["trace"])} tool call(s)</span></summary><div>'
    ]
    if not rec["trace"]:
        out.append('<p class="muted">No tool calls.</p>')
    for call in rec["trace"]:
        finding = bad.get(call["span_id"])
        args = json.dumps(call["args"], indent=2, ensure_ascii=False, default=str)
        out.append(
            f'<div class="span{" violation" if finding else ""}">'
            f'<code>span {call["span_id"]}: {escape(call["tool"])}</code>'
            f"<pre>{escape(args)}</pre>"
            f'<div class="muted"><code>→ {escape(str(call["result"]))}</code></div>'
        )
        for f in rec["findings"]:
            if f["span_id"] == call["span_id"]:
                out.append(f'<div class="finding">[{escape(f["invariant"])}] {escape(f["reason"])}</div>')
        out.append("</div>")
    if rec["final_text"]:
        out.append(f'<h3>Final reply</h3><pre>{escape(rec["final_text"])}</pre>')
    out.append("</div></details>")
    return "".join(out)


def _audit_html(audit: dict[str, Any]) -> list[str]:
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for f in audit["findings"]:
        by_tool.setdefault(f["tool"], []).append(f)
    out = [
        f'<h2>Server audit: {escape(audit["server"])}</h2>',
        f'<p class="muted"><code>{escape(" ".join(audit["command"]))}</code> · '
        f'{len(audit["tools"])} tools · {len(audit["findings"])} metadata indicator(s). '
        "Indicators are heuristic; the live canary test below is the evidence.</p>",
        '<div class="table-wrap"><table><tr><th>tool</th><th>indicators</th></tr>',
    ]
    for tool in audit["tools"]:
        hits = by_tool.get(tool["name"], [])
        cls = "rsome" if hits else "r0"
        out.append(
            f'<tr><td><code>{escape(tool["name"])}</code></td>'
            f'<td class="{cls}">{escape(", ".join(sorted({h["indicator"] for h in hits})) or "none")}</td></tr>'
        )
    out.append("</table></div>")
    for tool in audit["tools"]:
        hits = by_tool.get(tool["name"], [])
        if not hits:
            continue
        out.append(f'<details open><summary><code>{escape(tool["name"])}</code></summary><div>')
        out += [
            f'<p class="finding">{escape(h["indicator"])} <span class="muted">({escape(h["location"])})</span></p>'
            f'<pre>{escape(h["excerpt"])}</pre>'
            for h in hits
        ]
        out.append(f'<p class="muted">Full description:</p><pre>{escape(tool["description"])}</pre></div></details>')
    return out


def render_html(data: dict[str, Any]) -> str:
    records = data["records"]
    scenarios = list(dict.fromkeys(r["scenario"] for r in records))
    total = len(records)
    failed = sum(1 for r in records if not r["passed"])
    targets_all = list(dict.fromkeys(r["target"] for r in records))

    body = [
        "<h1>AgentRed report</h1>",
        f'<p class="muted">{escape(data["generated_at"])} · AgentRed {escape(data["agentred_version"])}'
        f' · <code>{escape(data["command"])}</code></p>',
        '<div class="stats">',
        f'<div class="stat"><b>{total}</b>trials</div>',
        f'<div class="stat"><b>{failed}</b>violations</div>',
        f'<div class="stat"><b>{len(scenarios)}</b>scenarios</div>',
        f'<div class="stat"><b>{len(targets_all)}</b>targets</div>',
        "</div>",
        '<p class="muted">Verdicts are deterministic checks over the recorded tool-call trace — '
        "what the agent did, not what it said. Click a cell to jump to its trials.</p>",
    ]

    for audit in data.get("audits", []):
        body += _audit_html(audit)

    for sid in scenarios:
        recs = [r for r in records if r["scenario"] == sid]
        first = recs[0]
        attacks = list(dict.fromkeys(r["attack"] for r in recs))
        targets = list(dict.fromkeys(r["target"] for r in recs))
        body.append(
            f'<h2>{escape(sid)} <span class="muted">· {escape(first["category"])}</span></h2>'
            f'<p class="muted">Invariant <code>{escape(first["invariant"])}</code> · '
            f'payload lands in <code>{escape(first["injection_point"])}</code></p>'
        )
        body.append('<div class="table-wrap"><table><tr><th>attack</th>')
        body += [f'<th style="text-align:center">{escape(t)}</th>' for t in targets]
        body.append("</tr>")
        for a in attacks:
            body.append(f"<tr><td><code>{escape(a)}</code></td>")
            for t in targets:
                cell = [r for r in recs if r["attack"] == a and r["target"] == t]
                if not cell:
                    body.append('<td class="cell muted">—</td>')
                    continue
                viol = sum(1 for r in cell if not r["passed"])
                body.append(
                    f'<td class="cell {_rate_class(viol, len(cell))}">'
                    f'<a href="#{_anchor(sid, a, t)}">{viol}/{len(cell)}</a></td>'
                )
            body.append("</tr>")
        body.append("</table></div>")

        for a in attacks:
            variant = next(r for r in recs if r["attack"] == a)
            body.append(f"<h3>Attack <code>{escape(a)}</code></h3>")
            body.append("<details><summary>Payload the agent saw</summary><div>")
            if variant["served_descriptions"]:
                for tool, desc in variant["served_descriptions"].items():
                    body.append(
                        f'<p class="muted">Tool description served for <code>{escape(tool)}</code> '
                        f"(tools/list):</p><pre>{escape(desc)}</pre>"
                    )
            body.append(f'<p class="muted">Task:</p><pre>{escape(variant["task"])}</pre></div></details>')
            for t in targets:
                cell = [r for r in recs if r["attack"] == a and r["target"] == t]
                if not cell:
                    continue
                viol = sum(1 for r in cell if not r["passed"])
                body.append(
                    f'<p id="{_anchor(sid, a, t)}"><b>{escape(t)}</b> '
                    f'<span class="muted">· {viol}/{len(cell)} violated</span></p>'
                )
                body += [_trial_html(r) for r in cell]

    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>AgentRed report</title><style>{_CSS}</style></head>"
        f"<body><main>{''.join(body)}</main></body></html>\n"
    )
