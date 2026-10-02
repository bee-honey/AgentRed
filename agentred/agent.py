"""The target agent: a minimal tool-use loop.

This is the thing under test. It is intentionally simple and intentionally
naive about trust — it treats retrieved content the same as its own
instructions, which is exactly the weakness v0.1 measures.

Tools come from a ToolProvider, so the agent is identical whether tools run
in-process or across a real MCP boundary; the provider owns the trace. The loop
maintains Anthropic-style message history so the real backend is natural; the
model backend itself is pluggable (see models.py).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .adapters import InProcessToolProvider, ToolProvider
from .models import Model
from .trace import Trace


@dataclass
class AgentRun:
    """The outcome of one agent execution: its trace and final reply."""

    trace: Trace
    final_text: str
    steps: int


class TargetAgent:
    def __init__(
        self,
        model: Model,
        system_prompt: str,
        tools: ToolProvider | None = None,
        max_steps: int = 6,
    ):
        self.model = model
        self.system_prompt = system_prompt
        self.tools: ToolProvider = tools or InProcessToolProvider()
        self.max_steps = max_steps

    def run(self, task: str, followups: tuple[str, ...] | list[str] = ()) -> AgentRun:
        """Run the task, then each follow-up user turn in the same conversation.

        Every user turn gets up to `max_steps` model calls. The final text joins
        the agent's reply to every turn, so checks over the reply see the whole
        conversation rather than only its last message.
        """
        schemas = self.tools.tool_schemas()
        messages: list[dict[str, Any]] = []
        replies: list[str] = []
        steps = 0
        for user_turn in (task, *followups):
            messages.append({"role": "user", "content": user_turn})
            reply, used = self._respond(messages, schemas)
            steps += used
            replies.append(reply)
            messages.append({"role": "assistant", "content": reply or "(no reply)"})
        return AgentRun(trace=self.tools.trace, final_text="\n\n".join(r for r in replies if r), steps=steps)

    def _respond(self, messages: list[dict[str, Any]], schemas: list[dict[str, Any]]) -> tuple[str, int]:
        """Model/tool loop for one user turn; returns the reply and steps used."""
        for step in range(1, self.max_steps + 1):
            turn = self.model.generate(self.system_prompt, messages, schemas)

            if not turn.wants_tools:
                return turn.text or "", step

            # Record the assistant turn (text + tool_use blocks) in history.
            assistant_content: list[dict[str, Any]] = []
            if turn.text:
                assistant_content.append({"type": "text", "text": turn.text})
            for tu in turn.tool_uses:
                assistant_content.append(
                    {"type": "tool_use", "id": tu.id, "name": tu.name, "input": tu.input}
                )
            messages.append({"role": "assistant", "content": assistant_content})

            # Execute each requested tool (through the provider) and feed results back.
            tool_results: list[dict[str, Any]] = []
            for tu in turn.tool_uses:
                result = self.tools.dispatch(tu.name, tu.input)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": tu.id, "content": str(result)}
                )
            messages.append({"role": "user", "content": tool_results})

        return "", self.max_steps
