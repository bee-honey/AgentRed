"""SARIF 2.1.0 output, so AgentRed findings flow into code-scanning tools and CI.

Each invariant violation in a report becomes one SARIF result: the rule is the
invariant, the level is error, and the logical location names the exact
scenario / design / attack / trial / span it came from. A stable
partialFingerprint lets a code-scanning backend match the same finding across
runs. There is no source file, so the physical location points at the report and
the detail lives in logicalLocations — valid SARIF that still renders in viewers
that expect an artifact.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .llm_judge import INVARIANT_RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/bee-honey/AgentRed"


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def report_to_sarif(data: dict[str, Any]) -> dict[str, Any]:
    records = data.get("records", [])
    invariants = sorted({r["invariant"] for r in records if not r["passed"]})
    rules = [
        {
            "id": inv,
            "name": inv,
            "shortDescription": {"text": INVARIANT_RULES.get(inv, inv)},
            "defaultConfiguration": {"level": "error"},
            "helpUri": INFO_URI,
        }
        for inv in invariants
    ]

    results = []
    for r in records:
        if r["passed"]:
            continue
        design = r.get("design", "prompt-only")
        where = f"{r['scenario']}/{design}/{r['attack']}/trial-{r['trial']}"
        for f in r["findings"]:
            results.append(
                {
                    "ruleId": f["invariant"],
                    "level": "error",
                    "message": {
                        "text": (
                            f"{r['scenario']} ({r['attack']}) on target {r['target']}: "
                            f"{f['reason']}"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {"artifactLocation": {"uri": "report.json"}},
                            "logicalLocations": [
                                {
                                    "fullyQualifiedName": f"{where}/span-{f['span_id']}",
                                    "name": f"span-{f['span_id']}",
                                    "kind": "member",
                                }
                            ],
                        }
                    ],
                    # Trial number is left out so re-runs match the same finding.
                    "partialFingerprints": {
                        "agentred/v1": _fingerprint(
                            r["scenario"], design, r["attack"], r["target"], f["invariant"], f["reason"]
                        )
                    },
                }
            )

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentRed",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
