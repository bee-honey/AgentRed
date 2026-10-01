"""The trace: AgentRed's ground truth.

Every tool the agent invokes is recorded here as a span. Evaluators judge the
recorded trace, never the agent's free-text reply — an agent saying "I won't do
that" is meaningless if the trace shows it already did.
"""

from __future__ import annotations

import itertools
import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """One recorded tool invocation."""

    name: str
    args: dict[str, Any]
    result: Any = None
    span_id: int = 0
    ts: float = field(default_factory=time.time)
    # True when a control refused the call before it reached the tool: the agent
    # *attempted* it, but nothing executed. Invariants judge executed calls only.
    blocked: bool = False

    def args_blob(self) -> str:
        """All argument values flattened to a searchable string.

        Used by deterministic checks (e.g. canary matching) that need to look
        for a token anywhere in the arguments regardless of nesting.
        """
        return json.dumps(self.args, default=str, ensure_ascii=False)


@dataclass
class Trace:
    """An ordered record of everything the agent did during one run."""

    calls: list[ToolCall] = field(default_factory=list)
    # The tool metadata the agent was served (tools/list), so a finding can
    # point at a poisoned description as well as at the call it caused.
    listed_tools: list[dict[str, Any]] = field(default_factory=list)
    _counter: Any = field(default_factory=lambda: itertools.count(1), repr=False)

    # Control events that aren't tool calls, e.g. a served tool description that
    # didn't match its pinned version.
    events: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self, name: str, args: dict[str, Any], result: Any = None, blocked: bool = False
    ) -> ToolCall:
        call = ToolCall(
            name=name, args=dict(args), result=result, span_id=next(self._counter), blocked=blocked
        )
        self.calls.append(call)
        return call

    @property
    def executed(self) -> list[ToolCall]:
        """Calls that actually ran (not blocked by a control)."""
        return [c for c in self.calls if not c.blocked]

    @property
    def blocked(self) -> list[ToolCall]:
        return [c for c in self.calls if c.blocked]

    def calls_to(self, tool_name: str) -> list[ToolCall]:
        return [c for c in self.calls if c.name == tool_name]
