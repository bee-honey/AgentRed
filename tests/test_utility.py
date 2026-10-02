"""Tests for task completion: security that breaks the job doesn't count."""

import json

import pytest

from agentred.designs import DESIGNS
from agentred.run import build_model, evaluate, main
from agentred.scenario import SCENARIOS
from agentred.utility import task_done, task_done_for_trace


@pytest.mark.parametrize("design", list(DESIGNS))
@pytest.mark.parametrize("scenario", list(SCENARIOS.values()), ids=list(SCENARIOS))
def test_careful_agent_completes_the_task_under_every_design(scenario, design):
    run, verdict = evaluate(scenario, build_model("scripted:careful", scenario), design=DESIGNS[design])
    assert verdict.passed
    assert task_done_for_trace(run.trace, run.final_text, scenario) is True


def test_blocked_calls_dont_count_as_doing_the_task():
    poisoning = SCENARIOS["poisoning"]
    run, _ = evaluate(poisoning, build_model("scripted:naive", poisoning), design=DESIGNS["guard-only"])
    assert run.trace.blocked and not run.trace.executed
    assert task_done_for_trace(run.trace, "Your order has shipped.", poisoning) is False


def test_task_checks_need_the_answer_not_just_the_call():
    authz = SCENARIOS["authz"]
    fetched = [("get_records", {"user": "alice"})]
    assert task_done(fetched, "Your balance is 12 days.", authz) is True
    assert task_done(fetched, "", authz) is False  # fetched it, never answered
    assert task_done([("get_records", {"user": "ceo"})], "12 days", authz) is False


def test_rescore_reads_saved_reports(tmp_path, capsys):
    out = tmp_path / "rep"
    main(["--designs", "prompt-only,guard-only", "--scenario", "authz", "--report", str(out)])
    capsys.readouterr()
    records = json.loads((out / "report.json").read_text())["records"]
    assert {r["task_done"] for r in records} == {False}  # naive agent ends with "Done."
    assert main(["rescore", str(out / "report.json")]) == 0
    text = capsys.readouterr().out
    assert "prompt-only" in text and "guard-only" in text and "task done" in text
