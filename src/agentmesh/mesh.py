"""The multi-agent runtime.

An agent's *brain* is a generator: it yields actions (call a tool, delegate to a sub-agent, run
several sub-agents in parallel) and receives observations. A scripted brain drives the offline
red team; an LLM adapter can drive the same loop.

What the mesh adds on top of single-agent safety:

* Delegation attenuates. A child gets ``parent_token.attenuate(...)``: strictly less authority.
* Labels cross agent boundaries. A child starts with its parent's context label (the task text
  may carry data), and whatever it returns carries the child's final label back to the parent.
  Parallel siblings are joined after they finish.
* Depth, agent count and step count are bounded, and everything is journaled.
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .broker import Broker
from .caps import CapabilityError, Token, remaining_depth
from .labels import PUBLIC, Label
from .util import clip


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    token: Token | None = None  # a compromised agent may present any token; the broker checks it


@dataclass(frozen=True)
class Delegate:
    role: str
    task: str
    brain: Callable[[AgentView], Any]
    caveats: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class Parallel:
    delegates: tuple[Delegate, ...]


@dataclass(frozen=True)
class AgentView:
    agent_id: str
    role: str
    task: str
    depth: int
    token: Token
    label: Label


@dataclass(frozen=True)
class Observation:
    status: str  # ok | denied | error | completed | max_steps | refused
    text: str
    label: Label = PUBLIC

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "completed")


@dataclass(frozen=True)
class AgentResult:
    agent_id: str
    role: str
    status: str
    output: str
    label: Label
    steps: int


class Mesh:
    def __init__(
        self,
        broker: Broker,
        *,
        max_depth: int = 4,
        max_steps: int = 30,
        max_agents: int = 64,
        propagate_labels: bool = True,
    ) -> None:
        self.broker = broker
        self.max_depth = max_depth
        self.max_steps = max_steps
        self.max_agents = max_agents
        self.propagate_labels = propagate_labels  # False exists only for mutation tests
        self.agents_started = 0
        self._lock = threading.Lock()

    def run(
        self, task: str, brain: Callable[[AgentView], Any], token: Token, *, role: str = "root"
    ) -> AgentResult:
        return self._agent(role, task, brain, token, PUBLIC, 0, None)

    # ------------------------------------------------------------------ one agent
    def _agent(
        self,
        role: str,
        task: str,
        brain: Callable[[AgentView], Any],
        token: Token,
        label: Label,
        depth: int,
        parent: str | None,
    ) -> AgentResult:
        with self._lock:
            if self.agents_started >= self.max_agents:
                return AgentResult(f"{role}#-", role, "refused", "agent limit reached", PUBLIC, 0)
            self.agents_started += 1
            agent_id = f"{role}#{self.agents_started}"
        journal = self.broker.journal
        journal.append(
            "agent_started",
            {
                "agent": agent_id,
                "parent": parent,
                "depth": depth,
                "task": clip(task),
                "label": label.to_dict(),
                "caveats": len(token.caveats),
            },
        )
        view = AgentView(agent_id, role, task, depth, token, label)
        status, output, steps = "completed", "", 0
        try:
            gen = brain(view)
            if not inspect.isgenerator(gen):
                output = str(gen)
            else:
                try:
                    action = next(gen)
                    while True:
                        steps += 1
                        if steps > self.max_steps:
                            status = "max_steps"
                            gen.close()
                            break
                        obs, label = self._act(action, agent_id, token, label, depth)
                        action = gen.send(obs)
                except StopIteration as stop:
                    output = "" if stop.value is None else str(stop.value)
        except Exception as exc:
            status, output = "error", f"{type(exc).__name__}: {exc}"
        journal.append(
            "agent_finished",
            {
                "agent": agent_id,
                "status": status,
                "steps": steps,
                "output": clip(output),
                "label": label.to_dict(),
            },
        )
        return AgentResult(agent_id, role, status, output, label, steps)

    # ------------------------------------------------------------------ actions
    def _act(self, action: Any, agent_id: str, token: Token, label: Label, depth: int) -> tuple[Any, Label]:
        if isinstance(action, Call):
            out = self.broker.call(action.token or token, action.tool, action.args, label, agent_id)
            if out.ok:
                label = label | out.label
            return Observation(out.status, out.text, out.label if out.ok else PUBLIC), label
        if isinstance(action, Delegate):
            result = self._delegate(action, agent_id, token, label, depth)
            return self._observe(result), self._join(label, [result])
        if isinstance(action, Parallel):
            with ThreadPoolExecutor(max_workers=max(1, len(action.delegates))) as pool:
                futures = [
                    pool.submit(self._delegate, d, agent_id, token, label, depth) for d in action.delegates
                ]
                results = [f.result() for f in futures]
            return [self._observe(r) for r in results], self._join(label, results)
        raise TypeError(f"unknown action {action!r}")

    def _join(self, label: Label, results: list[AgentResult]) -> Label:
        if not self.propagate_labels:
            return label
        for result in results:
            label = label | result.label
        return label

    def _observe(self, result: AgentResult) -> Observation:
        return Observation(result.status, result.output, result.label)

    def _delegate(self, d: Delegate, parent_id: str, token: Token, label: Label, depth: int) -> AgentResult:
        journal = self.broker.journal
        remaining = remaining_depth(token.caveats)
        if depth + 1 > self.max_depth or (remaining is not None and remaining <= 0):
            journal.append("delegation_refused", {"parent": parent_id, "role": d.role})
            return AgentResult(f"{d.role}#-", d.role, "refused", "delegation depth limit reached", PUBLIC, 0)
        child_remaining = remaining - 1 if remaining is not None else self.max_depth - depth - 1
        try:
            child_token = token.attenuate(*d.caveats, {"type": "depth", "remaining": child_remaining})
        except CapabilityError as exc:
            journal.append("delegation_refused", {"parent": parent_id, "role": d.role, "why": str(exc)})
            return AgentResult(f"{d.role}#-", d.role, "refused", f"invalid delegation: {exc}", PUBLIC, 0)
        journal.append(
            "delegation",
            {"parent": parent_id, "role": d.role, "added_caveats": [c["type"] for c in d.caveats]},
        )
        child_label = label if self.propagate_labels else PUBLIC
        return self._agent(d.role, d.task, d.brain, child_token, child_label, depth + 1, parent_id)
