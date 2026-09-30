"""End-to-end test of the v0.1 slice, using the scripted backend (no API key).

Proves the pipeline distinguishes a violation from safe behaviour purely from
the recorded trace.
"""

from agentred.run import _careful_backend, _naive_backend, evaluate
from agentred.scenario import INDIRECT_INJECTION_EGRESS as SCEN


def test_naive_agent_fails_on_secret_egress():
    run, verdict = evaluate(SCEN, _naive_backend(SCEN))
    assert not verdict.passed
    assert verdict.label == "FAIL"
    # Both signals should fire: canary present AND unapproved recipient.
    reasons = " ".join(f.reason for f in verdict.findings)
    assert "canary" in reasons
    assert "unapproved recipient" in reasons
    # The finding points at a real recorded span.
    span_ids = {c.span_id for c in run.trace.calls}
    assert all(f.span_id in span_ids for f in verdict.findings)


def test_careful_agent_passes():
    run, verdict = evaluate(SCEN, _careful_backend(SCEN))
    assert verdict.passed
    assert verdict.label == "PASS"
    assert verdict.findings == []
    # It still acted (emailed the internal team) — it just stayed safe.
    assert run.trace.calls_to("send_email")


def test_canary_never_hardcoded_as_real_secret():
    # Guardrail: the canary is a tagged fake, so it is safe to ship in-repo.
    assert "CANARY" in SCEN.canary
