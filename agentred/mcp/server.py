"""A minimal MCP server that speaks JSON-RPC 2.0 over stdio.

Register tools with `register(...)`, then call `serve()` to run the read/dispatch
loop on stdin/stdout. Supports `initialize`, `tools/list`, and `tools/call`.

A tool handler takes the call arguments (dict) and returns a string, which is
wrapped in a single text `content` block. Raising inside a handler is reported
back as an MCP tool error (`isError: true`), not a transport failure.
"""

from __future__ import annotations

import sys
import traceback
from dataclasses import dataclass
from typing import Any, Callable, TextIO

from . import jsonrpc

ToolHandler = Callable[[dict[str, Any]], str]


@dataclass
class _Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler


class MCPServer:
    def __init__(self, name: str, version: str = "0.1.0"):
        self.name = name
        self.version = version
        self._tools: dict[str, _Tool] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: ToolHandler,
    ) -> None:
        self._tools[name] = _Tool(name, description, input_schema, handler)

    # --- request handling ---

    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Return a response message, or None for notifications."""
        method = msg.get("method")
        msg_id = msg.get("id")

        if jsonrpc.is_notification(msg):
            return None  # e.g. notifications/initialized — nothing to reply

        if method == "initialize":
            return jsonrpc.result(
                msg_id,
                {
                    "protocolVersion": jsonrpc.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": self.version},
                },
            )

        if method == "tools/list":
            return jsonrpc.result(
                msg_id,
                {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        }
                        for t in self._tools.values()
                    ]
                },
            )

        if method == "tools/call":
            params = msg.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments", {})
            tool = self._tools.get(name)
            if tool is None:
                return jsonrpc.error(msg_id, jsonrpc.METHOD_NOT_FOUND, f"unknown tool {name!r}")
            try:
                text = tool.handler(arguments)
                return jsonrpc.result(
                    msg_id, {"content": [{"type": "text", "text": str(text)}], "isError": False}
                )
            except Exception as e:  # tool failure is reported in-band
                traceback.print_exc(file=sys.stderr)
                return jsonrpc.result(
                    msg_id,
                    {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True},
                )

        return jsonrpc.error(msg_id, jsonrpc.METHOD_NOT_FOUND, f"unknown method {method!r}")

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        while True:
            msg = jsonrpc.read_message(stdin)
            if msg is None:
                return
            response = self.handle(msg)
            if response is not None:
                jsonrpc.write_message(stdout, response)
