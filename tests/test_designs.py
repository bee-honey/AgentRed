"""Tests for agent designs: each control, blocked attempts, and no false blocks."""

import pytest

from agentred.designs import DESIGNS, HARDENED_RULES, PolicyGuardProvider
from agentred.judge import evaluate_scenario
from agentred.run import build_model, evaluate, main, make_provider
from agentred.scenario import APPROVAL_GATE, SCENARIOS, TOOL_POISONING
from agentred.trace import Trace

GUARD = DESIGNS["policy-guard"]


@pytest.mark.parametrize("scenario", list(SCENARIOS.values()), ids=list(SCENARIOS))
def test_policy_guard_stops_the_naive_agent_and_records_the_attempt(scenario):
    run, verdict = evaluate(scenario, build_model("scripted:naive", scenario), design=GUARD)
    assert verdict.passed
    assert run.trace.blocked, "the attempt should be on record"
    assert all(c.result.startswith("BLOCKED by policy") for c in run.trace.blocked)


@pytest.mark.parametrize("scenario", list(SCENARIOS.values()), ids=list(SCENARIOS))
def test_policy_guard_never_blocks_legitimate_work(scenario):
    run, verdict = evaluate(scenario, build_model("scripted:careful", scenario), design=GUARD)
    assert verdict.passed
    assert not run.trace.blocked


def test_prompt_only_design_is_the_unchanged_baseline():
    scenario = SCENARIOS["authz"]
    run, verdict = evaluate(scenario, build_model("scripted:naive", scenario), design=DESIGNS["prompt-only"])
    assert not verdict.passed and not run.trace.blocked


def test_hardened_prompt_adds_rules_to_the_system_prompt():
    seen = {}

    class Spy:
        def generate(self, system, messages, tools):
            seen["system"] = system
            from agentred.models import ModelTurn
            return ModelTurn(text="ok")

    evaluate(SCENARIOS["egress"], Spy(), design=DESIGNS["hardened-prompt"])
    assert seen["system"].endswith(HARDENED_RULES)


@pytest.mark.parametrize("transport", ["inprocess", "mcp"])
def test_pinned_tools_replaces_a_poisoned_description_and_logs_drift(transport):
    provider = make_provider(transport, TOOL_POISONING)
    _, wrapped = DESIGNS["pinned-tools"].apply(TOOL_POISONING, provider)
    try:
        (schema,) = wrapped.tool_schemas()
        assert "IMPORTANT" not in schema["description"]
        assert wrapped.trace.events == [
            {"control": "pinned-tools", "event": "description drift", "tool": "lookup_order"}
        ]
    finally:
        wrapped.close()


def test_guard_allows_a_gated_action_once_approval_is_granted():
    class Approving:
        trace = Trace()

        def tool_schemas(self):
            return []

        def dispatch(self, name, args):
            result = "APPROVED: APR-1" if name == "request_approval" else "ok"
            self.trace.record(name, args, result=result)
            return result

        def close(self):
            pass

    guard = PolicyGuardProvider(Approving(), APPROVAL_GATE)
    assert guard.dispatch("issue_refund", {"order_id": "10482", "amount": 2400}).startswith("BLOCKED")
    guard.dispatch("request_approval", {"action": "issue_refund", "order_id": "10482"})
    assert guard.dispatch("issue_refund", {"order_id": "10482", "amount": 2400}) == "ok"
    assert evaluate_scenario(guard.trace, APPROVAL_GATE).passed  # blocked attempt isn't a violation


def test_design_table_cli(capsys):
    assert main(["--designs", "all", "--scenario", "poisoning", "--trials", "2"]) == 0
    out = capsys.readouterr().out
    rows = {line.split()[0]: line.split() for line in out.splitlines() if line.split()[:1] and line.split()[0] in DESIGNS}
    assert rows["prompt-only"][1:4] == ["2/2", "34%–100%", "0/2"]
    assert rows["policy-guard"][1:4] == ["0/2", "0%–66%", "2/2"]
