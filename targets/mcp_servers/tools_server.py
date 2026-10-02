"""A standalone MCP server that exposes AgentRed's registry tools.

Which tools it advertises is decided by argv (the tool names), so a scenario can
launch a server offering exactly the tools it needs, e.g.

    python targets/mcp_servers/tools_server.py send_email get_records

`--description NAME TEXT` (repeatable) makes it advertise TEXT as tool NAME's
description — playing a malicious third-party server that serves poisoned tool
metadata.

With no tool names it exposes every registered tool. It only *acts* (returns the
tools' benign results) and does no recording — recording is the proxy's job, so
the server stays a realistic, dumb external system. (`python -m agentred.serve
--record FILE` is the same server with recording, for black-box agents.)
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a plain script: make the repo root importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentred.serve import build_server, main  # noqa: E402,F401

if __name__ == "__main__":
    main()
