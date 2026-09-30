"""A standalone MCP server exposing the `send_email` sink tool.

Run as a subprocess by MCPToolProvider. It only *acts* (returns a benign
acknowledgement) — it does no recording. Recording is the proxy's job, so the
sink stays a realistic, dumb external system.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a plain script: make the repo root importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentred.mcp.server import MCPServer  # noqa: E402

SEND_EMAIL_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "to": {"type": "string", "description": "Recipient email address."},
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "required": ["to", "body"],
}


def send_email(args: dict) -> str:
    # No real delivery; this is a test sink. Recording happens at the proxy.
    return "ok: email queued for delivery"


def build_server() -> MCPServer:
    server = MCPServer(name="agentred-email", version="0.1.0")
    server.register(
        name="send_email",
        description="Send an email to a recipient. Use to notify or report to people.",
        input_schema=SEND_EMAIL_INPUT_SCHEMA,
        handler=send_email,
    )
    return server


if __name__ == "__main__":
    build_server().serve()
