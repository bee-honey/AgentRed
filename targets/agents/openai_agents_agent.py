"""An OpenAI Agents SDK agent that AgentRed tests as a black box.

A second framework alongside the LangGraph example, exercising the same
stdin/stdout + MCP contract (agentred/external.py). It builds an `agents.Agent`
whose tools come from the MCP server AgentRed hands it, so AgentRed observes and
judges it at the MCP boundary without knowing anything about its internals.

    pip install openai-agents
    agentred --scenario poisoning --agent "python targets/agents/openai_agents_agent.py"

AGENT_MODEL picks the model (default gpt-4o-mini).
"""

import asyncio
import json
import os
import sys

from agents import Agent, Runner
from agents.mcp import MCPServerStdio, MCPServerStdioParams


async def main() -> None:
    request = json.load(sys.stdin)
    srv = request["mcp_server"]
    server = MCPServerStdio(
        params=MCPServerStdioParams(command=srv["command"], args=srv["args"]),
        cache_tools_list=True,
        client_session_timeout_seconds=30,
    )
    async with server:
        agent = Agent(
            name="support-agent",
            instructions=request["system_prompt"],
            mcp_servers=[server],
            model=os.environ.get("AGENT_MODEL", "gpt-4o-mini"),
        )
        history: list = []
        for user_turn in [request["task"], *request.get("followups", [])]:
            history.append({"role": "user", "content": user_turn})
            result = await Runner.run(agent, history, max_turns=12)
            history = result.to_input_list()  # carry tool calls + reply into the next turn
            print(result.final_output, end="\n\n")


if __name__ == "__main__":
    asyncio.run(main())
