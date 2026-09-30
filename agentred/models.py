"""Pluggable model backends behind one tiny interface.

The agent loop only needs `generate(system, messages, tools) -> ModelTurn`.

- `ScriptedModel` returns predetermined turns, so the whole pipeline runs with
  no API key (used by the tests and the offline demo).
- `AnthropicModel` calls the real Claude Messages API, so the same harness can
  measure an actual agent's behaviour.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolUse:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class ModelTurn:
    """One assistant turn: some text and/or one or more tool-use requests."""

    text: str | None = None
    tool_uses: list[ToolUse] = field(default_factory=list)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_uses)


class Model(Protocol):
    def generate(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ModelTurn: ...


class ScriptedModel:
    """Replays a fixed list of turns. `messages`/`tools` are ignored.

    Lets us drive the exact agent behaviour we want to demonstrate (e.g. an
    agent that follows an injected instruction) without a network call.
    """

    def __init__(self, turns: list[ModelTurn]):
        self._turns = list(turns)
        self._i = 0

    def generate(self, system, messages, tools) -> ModelTurn:  # noqa: ARG002
        if self._i >= len(self._turns):
            # Nothing left to say: end the loop with an empty text turn.
            return ModelTurn(text="")
        turn = self._turns[self._i]
        self._i += 1
        return turn


class AnthropicModel:
    """Real Claude backend. Requires the `anthropic` package and an API key."""

    def __init__(self, model: str = "claude-opus-4-8", max_tokens: int = 1024):
        try:
            import anthropic  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover - env dependent
            raise RuntimeError(
                "AnthropicModel needs the 'anthropic' package: pip install anthropic"
            ) from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic()
        self._model = model
        self._max_tokens = max_tokens

    def generate(self, system, messages, tools) -> ModelTurn:  # pragma: no cover - network
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=messages,
            tools=[
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t["input_schema"],
                }
                for t in tools
            ],
        )
        text_parts: list[str] = []
        tool_uses: list[ToolUse] = []
        for block in resp.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_uses.append(ToolUse(id=block.id, name=block.name, input=dict(block.input)))
        return ModelTurn(text="\n".join(text_parts) or None, tool_uses=tool_uses)
