"""`agentred gate`: fail when an agent's security regresses against a baseline.

Regression testing for agent security. A baseline is a saved `report.json`; the
current run is another. For each cell — a (scenario, target, attack) triple — the
gate compares violation rates. A cell whose current rate is higher than the
baseline's (beyond a tolerance) is a regression, and the gate exits non-zero so
CI can block the change. Cells that improve are reported too.

Run offline so it is deterministic and needs no API key: the scripted backend
replays fixed behaviour, so the gate only moves when the agent's own code moves
(for example a control that stops blocking).

    agentred gate --baseline agentred-baseline.json agentred-report/report.json
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Cell:
    scenario: str
    target: str
    attack: str
    violations: int
    trials: int

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.scenario, self.target, self.attack)

    @property
    def rate(self) -> float:
        return self.violations / self.trials if self.trials else 0.0


def cells(report: dict[str, Any]) -> dict[tuple[str, str, str], Cell]:
    agg: dict[tuple[str, str, str], list[int]] = {}
    for r in report.get("records", []):
        key = (r["scenario"], r["target"], r["attack"])
        v, n = agg.setdefault(key, [0, 0])
        agg[key] = [v + (not r["passed"]), n + 1]
    return {k: Cell(*k, v, n) for k, (v, n) in agg.items()}


def compare(baseline: dict[str, Any], current: dict[str, Any], tol: float = 0.0):
    """Return (regressions, improvements) as (Cell_current, baseline_rate) pairs."""
    base = cells(baseline)
    cur = cells(current)
    regressions, improvements = [], []
    for key, c in cur.items():
        base_rate = base[key].rate if key in base else 0.0  # a new failing cell regresses from 0
        if c.rate > base_rate + tol:
            regressions.append((c, base_rate))
        elif c.rate < base_rate - tol:
            improvements.append((c, base_rate))
    return regressions, improvements


def gate_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="agentred gate",
        description="Fail if a current report regresses against a baseline report.",
    )
    parser.add_argument("current", help="current report.json")
    parser.add_argument("--baseline", required=True, help="baseline report.json")
    parser.add_argument(
        "--tolerance", type=float, default=0.0,
        help="allowed rise in violation rate per cell before it counts as a regression (0-1)",
    )
    args = parser.parse_args(argv)

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    regressions, improvements = compare(baseline, current, args.tolerance)

    print("=" * 64)
    print("AgentRed gate — security regression check")
    print(f"  baseline: {args.baseline}")
    print(f"  current : {args.current}")
    print("=" * 64)
    for c, base_rate in improvements:
        print(f"  improved  {c.scenario}/{c.target}/{c.attack}: "
              f"{base_rate:.0%} -> {c.rate:.0%} ({c.violations}/{c.trials})")
    if not regressions:
        print(f"\nPASS — no agent-security regressions ({len(improvements)} improvement(s)).")
        print("=" * 64)
        return 0
    print(f"\nFAIL — {len(regressions)} regression(s):")
    for c, base_rate in regressions:
        print(f"  {c.scenario}/{c.target}/{c.attack}: "
              f"{base_rate:.0%} -> {c.rate:.0%} ({c.violations}/{c.trials} now violating)")
    print("=" * 64)
    return 1
