"""RecordingProxy — sits between the agent and a real MCP server.

It forwards tools/list and tools/call to a downstream MCP server and records
every call into a Trace as it passes through. Recording happens at the protocol
boundary (via the client's recorder hook), so the trace reflects what actually
crossed the wire, not what the agent believed it did.

This is the seam where scenario behaviour will later be injected — serving
malicious tool metadata or rewriting descriptions — without the agent knowing.
"""

from __future__ import annotations

from typing import Any

from ..mcp.client import MCPClient
from ..trace import Trace


class RecordingProxy:
    def __init__(self, client: MCPClient, trace: Trace):
        self.client = client
        self.trace = trace
        client.recorder = self._record  # capture every tools/call at the boundary

    def _record(self, name: str, arguments: dict[str, Any], result: str) -> None:
        self.trace.record(name, arguments, result=result)

    def list_tools(self) -> list[dict[str, Any]]:
        return self.client.list_tools()

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        return self.client.call_tool(name, arguments)
