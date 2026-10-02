"""Run an agent AgentRed didn't write, as a black box.

The contract is deliberately small, so any framework or language can meet it:

  stdin   one JSON object:
            {"system_prompt": "...", "task": "...",
             "mcp_server": {"command": "...", "args": ["..."]}}
  stdout  the agent's final reply (stderr is ignored)

The agent connects to the MCP server it's given — a recording server
(`agentred.serve`) offering the scenario's tools — does the task, and exits.
AgentRed then reads what was recorded at that MCP boundary and judges it exactly
as it judges its own agent. Nothing about the agent's internals is assumed.

    agentred --scenario poisoning --agent "python targets/agents/langgraph_agent.py"
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .agent import AgentRun
from .scenario import Scenario
from .tools import model_schemas
from .trace import Trace


def agent_label(command: list[str]) -> str:
    """'agent:<script>' — the first argument that looks like a file, else the program."""
    script = next(
        (p for p in command[1:] if not p.startswith("-") and ("/" in p or Path(p).suffix)),
        command[0],
    )
    return f"agent:{Path(script).stem}"


def run_external(scenario: Scenario, command: list[str], timeout: float = 300.0) -> AgentRun:
    if scenario.server_command:
        raise ValueError("black-box agents run built-in scenarios, not third-party server scans")
    with tempfile.TemporaryDirectory(prefix="agentred-") as tmp:
        record = str(Path(tmp) / "calls.jsonl")
        server_args = ["-m", "agentred.serve", "--record", record]
        for tool, description in scenario.description_overrides.items():
            server_args += ["--description", tool, description]
        server_args += list(scenario.tools)
        payload = {
            "system_prompt": scenario.system_prompt,
            "task": scenario.task,
            "mcp_server": {"command": sys.executable, "args": server_args},
        }
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [str(Path(__file__).resolve().parents[1]), os.environ.get("PYTHONPATH")]))}
        try:
            proc = subprocess.run(
                command, input=json.dumps(payload), capture_output=True, text=True,
                timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"agent {command!r} timed out after {timeout:g}s") from None
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-3:]
            raise RuntimeError(f"agent exited {proc.returncode}: {' | '.join(tail)}")

        trace = Trace()
        trace.listed_tools = model_schemas(scenario.tools, scenario.description_overrides)
        if os.path.exists(record):
            for line in Path(record).read_text(encoding="utf-8").splitlines():
                call = json.loads(line)
                trace.record(call["tool"], call["args"], result=call["result"])
    return AgentRun(trace=trace, final_text=proc.stdout.strip(), steps=0)
