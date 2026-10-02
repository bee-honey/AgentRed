"""Tests for SARIF output and the regression gate."""

import json

import pytest

from agentred.gate import cells, compare
from agentred.run import main
from agentred.sarif import report_to_sarif


def _report(tmp_path, scenario="poisoning", designs="prompt-only,policy-guard"):
    out = tmp_path / "rep"
    main(["--designs", designs, "--scenario", scenario, "--report", str(out)])
    return json.loads((out / "report.json").read_text()), out


def test_sarif_is_valid_2_1_0_with_rules_and_results(tmp_path):
    data, out = _report(tmp_path)
    sarif = json.loads((out / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AgentRed"
    assert "NO_SECRET_EGRESS" in {r["id"] for r in driver["rules"]}
    results = sarif["runs"][0]["results"]
    assert results and all(r["level"] == "error" for r in results)
    # prompt-only violates, policy-guard doesn't: every result is a real violation
    assert all("NO_SECRET_EGRESS" == r["ruleId"] for r in results)
    loc = results[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]
    assert loc.startswith("poisoning/prompt-only/")


def test_sarif_fingerprint_is_stable_across_runs_and_ignores_trial(tmp_path):
    a = report_to_sarif(_report(tmp_path / "a")[0])
    b = report_to_sarif(_report(tmp_path / "b")[0])
    fp = lambda s: sorted(r["partialFingerprints"]["agentred/v1"] for r in s["runs"][0]["results"])
    assert fp(a) == fp(b)  # same finding, same fingerprint run to run


def test_gate_passes_on_identical_and_flags_regression(tmp_path, capsys):
    data, out = _report(tmp_path)
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(data))
    assert main(["gate", "--baseline", str(base), str(out / "report.json")]) == 0

    # make policy-guard start violating -> regression
    for r in data["records"]:
        if r["target"] == "policy-guard":
            r["passed"], r["findings"] = False, [{"span_id": 1, "invariant": "NO_SECRET_EGRESS", "reason": "leak"}]
    regressed = tmp_path / "regressed.json"
    regressed.write_text(json.dumps(data))
    assert main(["gate", "--baseline", str(base), str(regressed)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_compare_detects_new_failing_cell_and_improvement():
    base = {"records": [{"scenario": "s", "target": "t", "attack": "a", "passed": True, "findings": []}]}
    worse = {"records": [{"scenario": "s", "target": "t", "attack": "a", "passed": False, "findings": []}]}
    regs, imps = compare(base, worse)
    assert len(regs) == 1 and not imps
    regs2, imps2 = compare(worse, base)  # the other direction is an improvement
    assert not regs2 and len(imps2) == 1


def test_gate_tolerance_allows_small_rises():
    base = {"records": [{"scenario": "s", "target": "t", "attack": "a", "passed": True, "findings": []}] * 10}
    one_fail = [{"scenario": "s", "target": "t", "attack": "a", "passed": True, "findings": []}] * 9
    one_fail += [{"scenario": "s", "target": "t", "attack": "a", "passed": False, "findings": []}]
    cur = {"records": one_fail}
    assert compare(base, cur, tol=0.0)[0]       # 0% -> 10% is a regression at tol 0
    assert not compare(base, cur, tol=0.1)[0]   # within tolerance
