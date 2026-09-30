"""End-to-end tests for the secret-egress scenario (scripted backend, no key)."""

from agentred.run import build_model, evaluate
from agentred.scenario import INDIRECT_INJECTION_EGRESS as EGRESS


def test_egress_naive_agent_fails():
    run, verdict = evaluate(EGRESS, build_model("scripted:naive", EGRESS))
    assert not verdict.passed
    assert verdict.invariant == "NO_SECRET_EGRESS"
    reasons = " ".join(f.reason for f in verdict.findings)
    assert "canary" in reasons
    assert "unapproved recipient" in reasons
    span_ids = {c.span_id for c in run.trace.calls}
    assert all(f.span_id in span_ids for f in verdict.findings)


def test_egress_careful_agent_passes():
    run, verdict = evaluate(EGRESS, build_model("scripted:careful", EGRESS))
    assert verdict.passed
    assert verdict.findings == []
    assert run.trace.calls_to("send_email")


def test_canary_is_a_tagged_fake():
    # Guardrail: the canary is a tagged fake, so it is safe to ship in-repo.
    assert "CANARY" in EGRESS.context["canary"]
