"""A recording MCP server for black-box agents.

    python -m agentred.serve --record calls.jsonl [--description NAME TEXT]...
        [--documents TEXT] TOOL...

When the agent under test isn't AgentRed's own loop, AgentRed can't record from
inside it. Instead the agent connects to this server, which offers a scenario's
tools (with any poisoned descriptions) and appends every tools/call it receives,
with its result, to a JSONL file. That file becomes the trace the invariants are
judged on — recorded at the MCP boundary, whatever framework or language the
agent is written in.

Without --record it's a plain tool server (this is what
targets/mcp_servers/tools_server.py runs).
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .mcp.server import MCPServer
from .tools import TOOL_REGISTRY, ToolHandler, model_schemas


def _recording(name: str, handler: ToolHandler, path: str) -> ToolHandler:
    def run(args: dict[str, Any]) -> str:
        result = handler(args)
        with open(path, "a", encoding="utf-8") as f:  # append: an agent may open several sessions
            f.write(json.dumps({"tool": name, "args": args, "result": result}) + "\n")
        return result

    return run


def build_server(
    tool_names: list[str],
    description_overrides: dict[str, str] | None = None,
    record: str | None = None,
    retrieved_content: str = "",
) -> MCPServer:
    server = MCPServer(name="agentred-tools", version="0.1.0")
    for schema in model_schemas(tuple(tool_names), description_overrides):
        handler = TOOL_REGISTRY[schema["name"]].handler
        if schema["name"] == "search_docs" and retrieved_content:
            handler = lambda args, _c=retrieved_content: _c  # scenario documents
        server.register(
            name=schema["name"],
            description=schema["description"],
            input_schema=schema["input_schema"],
            handler=_recording(schema["name"], handler, record) if record else handler,
        )
    return server


def parse_args(argv: list[str]) -> tuple[list[str], dict[str, str], str | None, str]:
    argv = list(argv)
    overrides: dict[str, str] = {}
    record = None
    retrieved = ""
    while "--description" in argv:
        i = argv.index("--description")
        overrides[argv[i + 1]] = argv[i + 2]
        del argv[i : i + 3]
    if "--record" in argv:
        i = argv.index("--record")
        record = argv[i + 1]
        del argv[i : i + 2]
    if "--documents" in argv:
        i = argv.index("--documents")
        retrieved = argv[i + 1]
        del argv[i : i + 2]
    return argv or list(TOOL_REGISTRY), overrides, record, retrieved


def main(argv: list[str] | None = None) -> None:
    names, overrides, record, retrieved = parse_args(sys.argv[1:] if argv is None else argv)
    build_server(names, overrides, record, retrieved).serve()


if __name__ == "__main__":
    main()
