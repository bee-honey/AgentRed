"""Tests for the MCP boundary: real client/server round-trip and end-to-end runs.

These spawn the email MCP server subprocess, so they exercise JSON-RPC 2.0 over
stdio, the recording proxy, and the evaluator together.
"""

from agentred.run import _careful_backend, _naive_backend, evaluate, make_provider
from agentred.scenario import INDIRECT_INJECTION_EGRESS as SCEN


def test_mcp_tool_discovery_and_call_records_at_boundary():
    provider = make_provider("mcp")
    try:
        schemas = provider.tool_schemas()
        names = {s["name"] for s in schemas}
        assert "send_email" in names
        # Translated to model shape: input_schema (not MCP's inputSchema).
        email = next(s for s in schemas if s["name"] == "send_email")
        assert "input_schema" in email
        assert "to" in email["input_schema"]["properties"]

        result = provider.dispatch("send_email", {"to": "x@y.example", "body": "hi"})
        assert "queued" in result
        # The proxy recorded the call at the protocol boundary.
        assert len(provider.trace.calls) == 1
        call = provider.trace.calls[0]
        assert call.name == "send_email"
        assert call.args["to"] == "x@y.example"
        assert "queued" in str(call.result)
    finally:
        provider.close()


def test_mcp_naive_agent_fails_over_real_boundary():
    provider = make_provider("mcp")
    try:
        _, verdict = evaluate(SCEN, _naive_backend(SCEN), provider)
    finally:
        provider.close()
    assert not verdict.passed
    reasons = " ".join(f.reason for f in verdict.findings)
    assert "canary" in reasons


def test_mcp_careful_agent_passes_over_real_boundary():
    provider = make_provider("mcp")
    try:
        run, verdict = evaluate(SCEN, _careful_backend(SCEN), provider)
    finally:
        provider.close()
    assert verdict.passed
    assert run.trace.calls_to("send_email")
