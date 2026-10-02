"""Generate docs/demo.svg: an animated terminal showing a real offline AgentRed run.

Runs the command for real (the offline scripted demo, so no API key is needed and
the output is reproducible), then renders a self-contained SVG terminal that types
the command and reveals the output. Animation uses SMIL so it plays on GitHub.

    python scripts/make_demo_svg.py
"""

from __future__ import annotations

import html
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN_CMD = [sys.executable, "-m", "agentred.run", "--scenario", "poisoning"]
DISPLAY_CMD = ["agentred", "--scenario", "poisoning"]

# Terminal geometry
FONT = 14
CW = 8.4  # monospace char width
LH = 20  # line height
PAD = 18
TOP = 44  # title bar height

# Palette (dark terminal)
BG = "#161615"
BAR = "#23231f"
FG = "#ecebe7"
MUTED = "#9b9a94"
GREEN = "#7ee2a0"
RED = "#ff8a80"
PROMPT = "#7aa2f7"


def color_for(line: str) -> str:
    s = line.strip()
    if s.startswith("VERDICT: PASS"):
        return GREEN
    if s.startswith("VERDICT: FAIL") or s.startswith("- [") or "canary secret" in s:
        return RED
    if set(s) == {"="} or s.startswith(("Scenario :", "Invariant:", "Trace (")):
        return MUTED
    return FG


def main() -> None:
    out = subprocess.run(RUN_CMD, cwd=ROOT, capture_output=True, text=True).stdout
    lines = [ln.rstrip() for ln in out.splitlines()]
    cmd_text = "$ " + " ".join(DISPLAY_CMD)

    cols = max(len(cmd_text), *(len(ln) for ln in lines)) + 2
    rows = len(lines) + 2  # command + blank + output
    width = round(PAD * 2 + cols * CW)
    height = round(TOP + PAD + rows * LH)

    # The command types out char by char, then output lines fade in in sequence,
    # then the whole thing holds and loops.
    type_dur = 1.4
    per_line = 0.12
    reveal_start = type_dur + 0.3
    total = reveal_start + len(lines) * per_line + 2.0

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" '
        f'font-size="{FONT}">',
        f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>',
        f'<rect width="{width}" height="{TOP}" rx="10" fill="{BAR}"/>',
        f'<rect y="{TOP - 10}" width="{width}" height="10" fill="{BAR}"/>',
    ]
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        parts.append(f'<circle cx="{22 + i * 20}" cy="{TOP // 2}" r="6" fill="{c}"/>')
    parts.append(
        f'<text x="{width/2}" y="{TOP/2 + 4}" fill="{MUTED}" text-anchor="middle" '
        f'font-size="12">AgentRed — judge the trace, not the text</text>'
    )

    y0 = TOP + PAD + LH
    # Typed command line, revealed with a clip that grows, plus a blinking cursor.
    parts.append(
        f'<text x="{PAD}" y="{y0}" fill="{PROMPT}" xml:space="preserve" '
        f'clip-path="url(#type)">{html.escape(cmd_text)}</text>'
    )
    clip_w_to = round(len(cmd_text) * CW) + 2
    # Default state (no animation support): full width, so the whole frame shows.
    parts.append(
        f'<clipPath id="type"><rect x="{PAD}" y="{y0 - LH}" height="{LH}" width="{clip_w_to}">'
        f'<set attributeName="width" to="0" begin="0s;loop.end"/>'
        f'<animate attributeName="width" from="0" to="{clip_w_to}" '
        f'dur="{type_dur}s" begin="0s;loop.end" fill="freeze" calcMode="linear"/>'
        f'</rect></clipPath>'
    )
    # Blinking cursor that sits at the end of the command once typed.
    parts.append(
        f'<rect x="{PAD + clip_w_to}" y="{y0 - 13}" width="8" height="16" fill="{FG}" opacity="0">'
        f'<animate attributeName="opacity" values="0;0;1;0;1;0;1" '
        f'keyTimes="0;{type_dur/total:.3f};{(type_dur+0.05)/total:.3f};'
        f'{(type_dur+0.4)/total:.3f};{(type_dur+0.8)/total:.3f};'
        f'{(type_dur+1.2)/total:.3f};{reveal_start/total:.3f}" '
        f'dur="{total}s" begin="0s" repeatCount="indefinite"/></rect>'
    )

    # Output lines, each fading in on its own schedule, held, then reset at loop.
    for i, ln in enumerate(lines):
        y = y0 + (i + 2) * LH
        begin = reveal_start + i * per_line
        parts.append(
            f'<text x="{PAD}" y="{y}" fill="{color_for(ln)}" xml:space="preserve" opacity="1">'
            f'{html.escape(ln) or " "}'
            f'<set attributeName="opacity" to="0" begin="0s;loop.end"/>'
            f'<animate attributeName="opacity" from="0" to="1" dur="0.18s" '
            f'begin="{begin:.2f}s;loop.end+{begin:.2f}s" fill="freeze"/>'
            f'</text>'
        )

    # The loop timer: an invisible element whose animation end restarts everything.
    parts.append(
        f'<rect width="1" height="1" opacity="0">'
        f'<animate id="loop" attributeName="x" from="0" to="1" dur="{total}s" '
        f'begin="0s;loop.end" calcMode="discrete"/></rect>'
    )
    parts.append("</svg>")

    dest = ROOT / "docs" / "demo.svg"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"wrote {dest} ({width}x{height}, {len(lines)} output lines)")


if __name__ == "__main__":
    sys.exit(main())
