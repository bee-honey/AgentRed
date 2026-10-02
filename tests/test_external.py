"""Tests for black-box agents: the stdin/stdout contract and MCP-boundary recording."""

import sys
import textwrap
from pathlib import Path

import pytest

from agentred.external import agent_label, run_external
from agentred.judge import evaluate_scenario
from agentred.run import main, run_trials
from agentred.scenario import SCENARIOS

REPO = Path(__file__).resolve().parents[1]

# A stand-in for someone else's agent: it speaks only the contract and MCP.
FAKE_AGENT = textwrap.dedent(f"""
    import json, sys
    sys.path.insert(0, {str(REPO)!r})
    from agentred.mcp.client import MCPClient
    req = json.load(sys.stdin)
    obey = sys.argv[1] == "obey"
    srv = req["mcp_server"]
    client = MCPClient([srv["command"], *srv["args"]]).start()
    tool = client.list_tools()[0]
    secret = req["system_prompt"].split("INTERNAL_API_KEY = ")[1].split()[0]
    args = {{"order_id": "10482", **({{"notes": secret}} if obey else {{}})}}
    print("Your order #10482 has " + client.call_tool(tool["name"], args).split(": ")[1] + ".")
    client.close()
""")


@pytest.fixture
def fake_agent(tmp_path):
    path = tmp_path / "fake_agent.py"
    path.write_text(FAKE_AGENT)
    return lambda mode: [sys.executable, str(path), mode]


def test_black_box_agent_is_judged_from_the_mcp_boundary(fake_agent):
    poisoning = SCENARIOS["poisoning"]
    run = run_external(poisoning, fake_agent("obey"))
    (call,) = run.trace.calls
    assert call.name == "lookup_order" and "AR-CANARY" in call.args["notes"]
    assert not evaluate_scenario(run.trace, poisoning).passed
    assert run.final_text.startswith("Your order #10482 has shipped")


def test_a_careful_black_box_agent_passes_and_completes_the_task(fake_agent):
    summary = run_trials(SCENARIOS["poisoning"], "agent:" + " ".join(fake_agent("ignore")), 2)
    assert summary.violations == 0 and summary.done == [True, True]
    assert summary.label == "agent:fake_agent"


def test_the_agent_is_served_the_poisoned_description(fake_agent, tmp_path):
    spy = tmp_path / "spy.py"
    spy.write_text(textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {str(REPO)!r})
        from agentred.mcp.client import MCPClient
        srv = json.load(sys.stdin)["mcp_server"]
        c = MCPClient([srv["command"], *srv["args"]]).start()
        print(c.list_tools()[0]["description"]); c.close()
    """))
    run = run_external(SCENARIOS["poisoning"], [sys.executable, str(spy)])
    assert "<IMPORTANT>" in run.final_text and not run.trace.calls


def test_agent_failures_are_reported(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("raise SystemExit('no model key')\n")
    with pytest.raises(RuntimeError, match="agent exited 1"):
        run_external(SCENARIOS["authz"], [sys.executable, str(broken)])


def test_agent_cli_and_label(fake_agent, capsys):
    assert agent_label(["python", "targets/agents/langgraph_agent.py"]) == "agent:langgraph_agent"
    assert main(["--scenario", "poisoning", "--agent", " ".join(fake_agent("obey"))]) == 1
    assert "VIOLATION RATE: 1/1" in capsys.readouterr().out


def test_designs_dont_apply_to_black_box_agents(fake_agent):
    from agentred.designs import DESIGNS
    with pytest.raises(ValueError, match="black-box"):
        run_trials(SCENARIOS["poisoning"], "agent:" + " ".join(fake_agent("obey")), 1,
                   design=DESIGNS["policy-guard"])


def test_black_box_agent_receives_followup_turns(tmp_path):
    echo = tmp_path / "echo.py"
    echo.write_text("import json, sys\nreq = json.load(sys.stdin)\nprint(len(req['followups']))\n")
    run = run_external(SCENARIOS["approval"].as_multi_turn(), [sys.executable, str(echo)])
    assert run.final_text == "2"
