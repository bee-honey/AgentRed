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


class OpenAIModel:
    """Real OpenAI backend. Requires the `openai` package and an API key.

    The agent keeps history in Anthropic block format, so this backend
    translates that history (and the tool schemas) into the OpenAI Chat
    Completions shape on each call, and normalises the reply back to a
    ModelTurn.
    """

    def __init__(self, model: str = "gpt-4o", max_tokens: int = 1024):
        try:
            import openai  # noqa: PLC0415
        except ImportError as e:  # pragma: no cover - env dependent
            raise RuntimeError(
                "OpenAIModel needs the 'openai' package: pip install openai"
            ) from e
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._client = openai.OpenAI()
        self._model = model
        self._max_tokens = max_tokens

    @staticmethod
    def _to_openai_messages(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        import json  # noqa: PLC0415

        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            role, content = m["role"], m["content"]
            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue
            if role == "assistant":
                text_parts, tool_calls = [], []
                for block in content:
                    if block["type"] == "text":
                        text_parts.append(block["text"])
                    elif block["type"] == "tool_use":
                        tool_calls.append(
                            {
                                "id": block["id"],
                                "type": "function",
                                "function": {
                                    "name": block["name"],
                                    "arguments": json.dumps(block["input"]),
                                },
                            }
                        )
                msg: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                out.append(msg)
            else:  # user turn carrying tool_result blocks
                for block in content:
                    if block["type"] == "tool_result":
                        out.append(
                            {
                                "role": "tool",
                                "tool_call_id": block["tool_use_id"],
                                "content": str(block["content"]),
                            }
                        )
        return out

    def generate(self, system, messages, tools) -> ModelTurn:  # pragma: no cover - network
        import json  # noqa: PLC0415

        kwargs: dict[str, Any] = {}
        if tools:  # the API rejects an empty tools list (e.g. for a judge call)
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in tools
            ]
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=self._to_openai_messages(system, messages),
            **kwargs,
        )
        msg = resp.choices[0].message
        tool_uses = [
            ToolUse(id=tc.id, name=tc.function.name, input=json.loads(tc.function.arguments or "{}"))
            for tc in (msg.tool_calls or [])
        ]
        return ModelTurn(text=msg.content or None, tool_uses=tool_uses)


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
