"""JSON-RPC 2.0 message helpers and newline-delimited stdio framing.

MCP's stdio transport carries one JSON-RPC message per line. These helpers build
and parse those messages and read/write them over text streams.
"""

from __future__ import annotations

import json
from typing import Any, TextIO

PROTOCOL_VERSION = "2024-11-05"

# Standard JSON-RPC error codes we use.
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603


def request(id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "method": method, "params": params or {}}


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params or {}}


def result(id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": payload}


def error(id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def write_message(stream: TextIO, msg: dict[str, Any]) -> None:
    """Write one message as a single line and flush (stdio framing)."""
    stream.write(json.dumps(msg, ensure_ascii=False) + "\n")
    stream.flush()


def read_message(stream: TextIO) -> dict[str, Any] | None:
    """Read one message. Returns None at end of stream. Skips blank lines."""
    while True:
        line = stream.readline()
        if line == "":  # EOF
            return None
        line = line.strip()
        if not line:
            continue
        return json.loads(line)


def is_notification(msg: dict[str, Any]) -> bool:
    return "id" not in msg and "method" in msg
