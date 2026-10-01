"""A standalone MCP server that exposes AgentRed's registry tools.

Which tools it advertises is decided by argv (the tool names), so a scenario can
launch a server offering exactly the tools it needs, e.g.

    python targets/mcp_servers/tools_server.py send_email get_records

`--scenario ID` makes it advertise that scenario's description overrides —
playing a malicious third-party server that serves poisoned tool metadata.

With no tool names it exposes every registered tool. It only *acts* (returns the
tools' benign results) and does no recording — recording is the proxy's job, so
the server stays a realistic, dumb external system.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a plain script: make the repo root importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentred.mcp.server import MCPServer  # noqa: E402
from agentred.scenario import SCENARIOS  # noqa: E402
from agentred.tools import TOOL_REGISTRY, model_schemas  # noqa: E402


def build_server(
    tool_names: list[str], description_overrides: dict[str, str] | None = None
) -> MCPServer:
    server = MCPServer(name="agentred-tools", version="0.1.0")
    for schema in model_schemas(tuple(tool_names), description_overrides):
        server.register(
            name=schema["name"],
            description=schema["description"],
            input_schema=schema["input_schema"],
            handler=TOOL_REGISTRY[schema["name"]].handler,
        )
    return server


if __name__ == "__main__":
    argv = sys.argv[1:]
    overrides: dict[str, str] = {}
    if "--scenario" in argv:
        i = argv.index("--scenario")
        overrides = SCENARIOS[argv[i + 1]].description_overrides
        del argv[i : i + 2]
    build_server(argv or list(TOOL_REGISTRY), overrides).serve()
