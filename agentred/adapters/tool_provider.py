"""Tool providers give the agent a uniform way to list and call tools.

Both take the scenario's tool names and expose the same interface, so the agent
is identical whether tools run in-process or across a real MCP boundary — only
the source of the trace changes.

- InProcessToolProvider: tools run in-process; the dispatcher records to the
  trace directly. Fast, no subprocess — used for the offline demo and unit tests.
- MCPToolProvider: tools live in a separate MCP server process; a RecordingProxy
  records every call at the JSON-RPC boundary.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..mcp.client import MCPClient
from ..proxy.recording_proxy import RecordingProxy
from ..tools import InstrumentedTools, model_schemas
from ..trace import Trace


class ToolProvider(Protocol):
    trace: Trace

    def tool_schemas(self) -> list[dict[str, Any]]:
        """Tools in model shape: {name, description, input_schema}."""
        ...

    def dispatch(self, name: str, args: dict[str, Any]) -> str: ...

    def close(self) -> None: ...


class InProcessToolProvider:
    def __init__(
        self, tool_names: tuple[str, ...], description_overrides: dict[str, str] | None = None
    ) -> None:
        self.trace = Trace()
        self._names = tuple(tool_names)
        self._overrides = dict(description_overrides or {})
        self._tools = InstrumentedTools(self.trace, self._names)

    def tool_schemas(self) -> list[dict[str, Any]]:
        schemas = model_schemas(self._names, self._overrides)
        self.trace.listed_tools = schemas
        return schemas

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        return self._tools.dispatch(name, args)

    def close(self) -> None:
        pass


def _to_model_schema(mcp_tool: dict[str, Any]) -> dict[str, Any]:
    """MCP `inputSchema` -> the `input_schema` key the model layer expects."""
    return {
        "name": mcp_tool["name"],
        "description": mcp_tool.get("description", ""),
        "input_schema": mcp_tool.get("inputSchema", {"type": "object", "properties": {}}),
    }


class MCPToolProvider:
    """Runs tools over a real MCP boundary and records via the proxy.

    `command` should launch the MCP server; the server decides which tools to
    advertise (here, from its argv). Usable as a context manager so the server
    subprocess is always cleaned up.
    """

    def __init__(self, command: list[str], cwd: str | None = None, **client_options: Any) -> None:
        self.trace = Trace()
        self._client = MCPClient(command, cwd=cwd, **client_options)
        self._proxy = RecordingProxy(self._client, self.trace)
        self._client.start()

    def tool_schemas(self) -> list[dict[str, Any]]:
        return [_to_model_schema(t) for t in self._proxy.list_tools()]

    def dispatch(self, name: str, args: dict[str, Any]) -> str:
        return self._proxy.call_tool(name, args)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "MCPToolProvider":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
