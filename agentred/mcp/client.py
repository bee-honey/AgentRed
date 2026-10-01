"""A minimal MCP client that spawns a server subprocess and speaks JSON-RPC 2.0.

Synchronous request/response over the child's stdio. On construction it performs
the `initialize` handshake and sends `notifications/initialized`.

A `recorder` callback, if given, fires on every `tools/call` with
(name, arguments, result_text) — this is where AgentRed captures tool traffic at
the protocol boundary. The recording proxy installs it.

Because it may talk to servers AgentRed didn't write, the client is defensive:
a background thread reads the server's stdout so every request has a timeout,
server-to-client requests are answered (`ping`) or refused (anything else)
instead of left hanging, and the caller controls the child's env and stderr.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
from typing import Any, Callable, TextIO

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
        env: dict[str, str] | None = None,
        stderr: TextIO | int | None = sys.stderr,
        timeout: float = 60.0,
    ):
        self.command = command
        self.cwd = cwd
        self.recorder = recorder
        self.env = env  # None inherits ours; pass a scrubbed copy for untrusted servers
        self.stderr = stderr  # sys.stderr surfaces tracebacks; DEVNULL silences chatty servers
        self.timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._inbox: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._next_id = 0

    # --- lifecycle ---

    def start(self) -> "MCPClient":
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            bufsize=1,  # line-buffered
            cwd=self.cwd,
            env=self.env,
        )
        threading.Thread(target=self._read_loop, daemon=True).start()
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

    def _read_loop(self) -> None:
        """Move every message from the server's stdout into the inbox; None marks EOF."""
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        while True:
            try:
                msg = jsonrpc.read_message(proc.stdout)
            except ValueError:
                continue  # a stray non-JSON line on stdout: skip it
            except OSError:
                msg = None  # closed pipe
            self._inbox.put(msg)
            if msg is None:
                return

    def _answer_server_request(self, msg: dict[str, Any]) -> None:
        proc = self._io()
        if msg["method"] == "ping":
            reply = jsonrpc.result(msg["id"], {})
        else:  # sampling, roots, elicitation, ...: this client offers none of them
            reply = jsonrpc.error(msg["id"], -32601, f"method not supported: {msg['method']}")
        jsonrpc.write_message(proc.stdin, reply)

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

        # Wait for the response matching our id; skip notifications, answer server requests.
        while True:
            try:
                msg = self._inbox.get(timeout=self.timeout)
            except queue.Empty:
                raise MCPClientError(f"no response to {method!r} within {self.timeout:g}s") from None
            if msg is None:
                raise MCPClientError(f"server closed the connection during {method!r}")
            if "method" in msg and "id" in msg:
                self._answer_server_request(msg)
                continue
            if msg.get("id") != req_id:
                continue
            if "error" in msg:
                raise MCPClientError(f"{method} failed: {msg['error']}")
            return msg.get("result", {})

    # --- MCP methods ---

    def list_tools(self) -> list[dict[str, Any]]:
        """Return tool definitions in MCP shape (name, description, inputSchema)."""
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page = self._rpc("tools/list", {"cursor": cursor} if cursor else None)
            tools += page.get("tools", [])
            cursor = page.get("nextCursor")
            if not cursor:
                return tools

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
