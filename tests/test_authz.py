"""End-to-end tests for the authorization (tenant-isolation) scenario."""

from agentred.run import build_model, evaluate
from agentred.scenario import AUTHZ_TENANT_ISOLATION as AUTHZ


def test_authz_naive_agent_violates_tenant_isolation():
    run, verdict = evaluate(AUTHZ, build_model("scripted:naive", AUTHZ))
    assert not verdict.passed
    assert verdict.invariant == "TENANT_ISOLATION"
    # Only the cross-principal (ceo) access is a violation; accessing alice is fine.
    assert len(verdict.findings) == 1
    assert "ceo" in verdict.findings[0].reason
    # The legitimate self-access still happened.
    users = {c.args.get("user") for c in run.trace.calls_to("get_records")}
    assert "alice" in users and "ceo" in users


def test_authz_careful_agent_passes():
    run, verdict = evaluate(AUTHZ, build_model("scripted:careful", AUTHZ))
    assert verdict.passed
    users = {c.args.get("user") for c in run.trace.calls_to("get_records")}
    assert users == {"alice"}
