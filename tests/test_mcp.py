"""Tests for the MCP boundary: real client/server round-trip and end-to-end runs.

These spawn the tools MCP server subprocess, so they exercise JSON-RPC 2.0 over
stdio, the recording proxy, and the evaluators together.
"""

from agentred.run import build_model, evaluate, make_provider
from agentred.scenario import AUTHZ_TENANT_ISOLATION as AUTHZ
from agentred.scenario import INDIRECT_INJECTION_EGRESS as EGRESS


def test_mcp_tool_discovery_and_call_records_at_boundary():
    provider = make_provider("mcp", EGRESS)
    try:
        schemas = provider.tool_schemas()
        names = {s["name"] for s in schemas}
        assert names == {"send_email"}  # scenario advertises exactly its tools
        email = next(s for s in schemas if s["name"] == "send_email")
        assert "input_schema" in email  # translated from MCP inputSchema
        assert "to" in email["input_schema"]["properties"]

        result = provider.dispatch("send_email", {"to": "x@y.example", "body": "hi"})
        assert "queued" in result
        assert len(provider.trace.calls) == 1
        call = provider.trace.calls[0]
        assert call.name == "send_email"
        assert call.args["to"] == "x@y.example"
    finally:
        provider.close()


def test_mcp_egress_naive_fails_over_real_boundary():
    provider = make_provider("mcp", EGRESS)
    try:
        _, verdict = evaluate(EGRESS, build_model("scripted:naive", EGRESS), provider)
    finally:
        provider.close()
    assert not verdict.passed
    assert any("canary" in f.reason for f in verdict.findings)


def test_mcp_authz_naive_fails_over_real_boundary():
    provider = make_provider("mcp", AUTHZ)
    try:
        run, verdict = evaluate(AUTHZ, build_model("scripted:naive", AUTHZ), provider)
    finally:
        provider.close()
    assert not verdict.passed
    assert any("ceo" in f.reason for f in verdict.findings)
    # The cross-principal access really crossed the MCP boundary and was recorded.
    assert "ceo" in {c.args.get("user") for c in run.trace.calls_to("get_records")}
