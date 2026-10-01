"""Tests for the JSON + HTML run report."""

import json

from agentred.run import main


def test_report_records_every_trial_with_trace_and_findings(tmp_path, capsys):
    out = tmp_path / "rep"
    assert main(["--scenario", "poisoning", "--attacks", "agentdojo", "--report", str(out)]) == 0
    data = json.loads((out / "report.json").read_text())
    recs = data["records"]
    assert len(recs) == 6 * 2  # (handwritten + 5 AgentDojo) x (naive, careful)
    naive = [r for r in recs if r["target"] == "scripted:naive"]
    assert all(not r["passed"] and r["findings"] for r in naive)
    # Findings point at a recorded span, and the poisoned metadata is kept as evidence.
    rec = naive[0]
    assert rec["findings"][0]["span_id"] in {c["span_id"] for c in rec["trace"]}
    assert "INTERNAL_API_KEY" in rec["served_descriptions"]["lookup_order"]
    assert "Report:" in capsys.readouterr().out


def test_html_report_is_self_contained_and_escaped(tmp_path):
    out = tmp_path / "rep"
    main(["--scenario", "poisoning", "--attacks", "agentdojo", "--report", str(out)])
    html = (out / "report.html").read_text()
    assert html.startswith("<!doctype html>")
    assert "<script" not in html and "http" not in html.split("</style>")[0]
    assert "&lt;IMPORTANT&gt;" in html  # the payload is shown, not interpreted
    assert 'href="#g-poisoning-important_instructions-scripted_naive"' in html
    assert 'id="g-poisoning-important_instructions-scripted_naive"' in html


def test_no_report_unless_asked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["--scenario", "authz"])
    assert not (tmp_path / "agentred-report").exists()
