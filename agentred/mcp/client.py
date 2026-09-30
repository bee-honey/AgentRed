"""A minimal MCP client that spawns a server subprocess and speaks JSON-RPC 2.0.

Synchronous request/response over the child's stdio. On construction it performs
the `initialize` handshake and sends `notifications/initialized`.

A `recorder` callback, if given, fires on every `tools/call` with
(name, arguments, result_text) — this is where AgentRed captures tool traffic at
the protocol boundary. The recording proxy installs it.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Callable

from . import jsonrpc

Recorder = Callable[[str, dict[str, Any], str], None]


class MCPClientError(RuntimeError):
    pass


class MCPClient:
    def __init__(
        self,
        command: list[str],
        cwd: str | None = None,
        recorder: Recorder | None = None,
    ):
        self.command = command
        self.cwd = cwd
        self.recorder = recorder
        self._proc: subprocess.Popen[str] | None = None
        self._next_id = 0

    # --- lifecycle ---

    def start(self) -> "MCPClient":
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # surface server tracebacks during development
            text=True,
            bufsize=1,  # line-buffered
            cwd=self.cwd,
        )
        self._rpc(
            "initialize",
            {
                "protocolVersion": jsonrpc.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentred", "version": "0.1.0"},
            },
        )
        self._notify("notifications/initialized")
        return self

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
        finally:
            self._proc = None

    def __enter__(self) -> "MCPClient":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- transport ---

    def _io(self) -> subprocess.Popen[str]:
        if self._proc is None or self._proc.stdin is None or self._proc.stdout is None:
            raise MCPClientError("client not started")
        return self._proc

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        proc = self._io()
        jsonrpc.write_message(proc.stdin, jsonrpc.notification(method, params))

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        proc = self._io()
        self._next_id += 1
        req_id = self._next_id
        jsonrpc.write_message(proc.stdin, jsonrpc.request(req_id, method, params))

        # Read until the response matching our id (skip any notifications).
        while True:
            msg = jsonrpc.read_message(proc.stdout)
            if msg is None:
                raise MCPClientError(f"server closed the connection during {method!r}")
            if msg.get("id") != req_id:
                continue
            if "error" in msg:
                raise MCPClientError(f"{method} failed: {msg['error']}")
            return msg.get("result", {})

    # --- MCP methods ---

    def list_tools(self) -> list[dict[str, Any]]:
        """Return tool definitions in MCP shape (name, description, inputSchema)."""
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(
            block.get("text", "")
            for block in result.get("content", [])
            if block.get("type") == "text"
        )
        if self.recorder is not None:
            self.recorder(name, arguments, text)
        return text
