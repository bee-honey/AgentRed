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
    _counter: Any = field(default_factory=lambda: itertools.count(1), repr=False)

    def record(self, name: str, args: dict[str, Any], result: Any = None) -> ToolCall:
        call = ToolCall(name=name, args=dict(args), result=result, span_id=next(self._counter))
        self.calls.append(call)
        return call

    def calls_to(self, tool_name: str) -> list[ToolCall]:
        return [c for c in self.calls if c.name == tool_name]
