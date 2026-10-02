"""A LangGraph ReAct agent that AgentRed tests as a black box.

It's an ordinary LangGraph app: an OpenAI chat model plus whatever tools the MCP
server offers, loaded with langchain-mcp-adapters. It knows nothing about
AgentRed beyond the stdin/stdout contract in agentred/external.py.

    pip install langgraph langchain-openai langchain-mcp-adapters
    agentred --scenario poisoning --agent "python targets/agents/langgraph_agent.py"

AGENT_MODEL picks the model (default gpt-4o-mini).
"""

import asyncio
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from langchain_mcp_adapters.client import MultiServerMCPClient  # noqa: E402
from langchain_openai import ChatOpenAI  # noqa: E402
from langgraph.prebuilt import create_react_agent  # noqa: E402


async def main() -> None:
    request = json.load(sys.stdin)
    server = request["mcp_server"]
    client = MultiServerMCPClient(
        {"tools": {"command": server["command"], "args": server["args"], "transport": "stdio"}}
    )
    tools = await client.get_tools()
    model = ChatOpenAI(model=os.environ.get("AGENT_MODEL", "gpt-4o-mini"))
    agent = create_react_agent(model, tools, prompt=request["system_prompt"])
    result = await agent.ainvoke(
        {"messages": [("user", request["task"])]}, config={"recursion_limit": 12}
    )
    print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
