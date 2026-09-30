"""A standalone MCP server that exposes AgentRed's registry tools.

Which tools it advertises is decided by argv (the tool names), so a scenario can
launch a server offering exactly the tools it needs, e.g.

    python targets/mcp_servers/tools_server.py send_email get_records

With no arguments it exposes every registered tool. It only *acts* (returns the
tools' benign results) and does no recording — recording is the proxy's job, so
the server stays a realistic, dumb external system.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a plain script: make the repo root importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentred.mcp.server import MCPServer  # noqa: E402
from agentred.tools import TOOL_REGISTRY  # noqa: E402


def build_server(tool_names: list[str]) -> MCPServer:
    server = MCPServer(name="agentred-tools", version="0.1.0")
    for name in tool_names:
        tool = TOOL_REGISTRY[name]
        server.register(
            name=tool.name,
            description=tool.schema["description"],
            input_schema=tool.schema["input_schema"],
            handler=tool.handler,
        )
    return server


if __name__ == "__main__":
    names = sys.argv[1:] or list(TOOL_REGISTRY)
    build_server(names).serve()
