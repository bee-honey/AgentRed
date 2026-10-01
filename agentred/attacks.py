"""Attack corpora: published injection templates applied to AgentRed scenarios.

A corpus is a JSON file of templates, each with a `{goal}` slot:

    {"source": "...", "url": "...", "license": "...",
     "attacks": [{"id": "direct", "template": "TODO: {goal}"}, ...]}

Applying an attack fills the template with the scenario's `injection_goal` and
places the result at the scenario's injection point (the task, or a tool
description). This is how AgentDojo itself pairs attacks with injection tasks,
so the violation rate comes from many attack styles instead of one hand-written
payload. Built-in corpora live in `agentred/corpora/`; any path to a JSON file
in the same shape works too.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .scenario import Scenario

CORPORA_DIR = Path(__file__).resolve().parent / "corpora"
HANDWRITTEN = "handwritten"


@dataclass(frozen=True)
class Attack:
    id: str
    source: str
    template: str

    def render(self, goal: str) -> str:
        return self.template.replace("{goal}", goal)


def builtin_corpora() -> list[str]:
    return sorted(p.stem for p in CORPORA_DIR.glob("*.json"))


def load_corpus(name_or_path: str) -> list[Attack]:
    """Load a built-in corpus by name (e.g. "agentdojo") or a JSON file by path."""
    path = CORPORA_DIR / f"{name_or_path}.json"
    if not path.exists():
        path = Path(name_or_path)
    if not path.exists():
        raise ValueError(
            f"unknown corpus {name_or_path!r}; built-in: {', '.join(builtin_corpora())}"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    source = data.get("source", path.stem)
    return [Attack(a["id"], source, a["template"]) for a in data["attacks"]]


def apply_attack(scenario: Scenario, attack: Attack) -> Scenario:
    """The scenario with this attack's payload at its injection point."""
    if not scenario.injection_goal:
        raise ValueError(f"scenario {scenario.id!r} declares no injection_goal")
    return scenario.with_injection(attack.render(scenario.injection_goal), attack.id)


def scenario_variants(scenario: Scenario, attacks: list[Attack]) -> list[Scenario]:
    """The hand-written scenario followed by one variant per corpus attack."""
    return [scenario, *(apply_attack(scenario, a) for a in attacks)]
