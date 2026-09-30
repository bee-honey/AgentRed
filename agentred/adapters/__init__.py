"""Tool providers: how the agent discovers and invokes tools.

Both providers expose the same interface (`tool_schemas()`, `dispatch()`, and a
`trace`), so the agent is identical whether tools run in-process or across a real
MCP boundary. Only the source of the trace changes.
"""

from .tool_provider import InProcessToolProvider, MCPToolProvider, ToolProvider

__all__ = ["ToolProvider", "InProcessToolProvider", "MCPToolProvider"]
