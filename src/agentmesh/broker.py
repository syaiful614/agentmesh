"""The broker: the single checkpoint every tool call must pass.

Order of checks for one call (each step can only make the outcome stricter):
  1. the token verifies against the authority (signature chain);
  2. every caveat holds (scope, argument constraints, budget, expiry, no_sinks);
  3. the policy decides allow / ask / deny for the tool;
  4. the flow check compares the caller's context label with the destination's clearance.

A DENY from step 4 cannot be overridden by a human approval: approval fatigue must not be able to
authorise a leak. Only ASK goes to the approver.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any

from .caps import Authority, CapabilityError, Token, evaluate
from .journal import Journal
from .labels import PUBLIC, Label
from .tools import ANY, Tool, ToolRegistry
from .util import clip


class Action(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    action: Action
    reason: str
    source: str  # rule | default | flow | capability | unknown_tool


@dataclass(frozen=True)
class Policy:
    rules: tuple[tuple[str, Action], ...] = ()
    default: Action = Action.ASK

    def evaluate(self, tool: Tool) -> Decision:
        for glob, action in self.rules:
            if fnmatchcase(tool.name, glob):
                return Decision(action, f"matched rule '{glob}'", "rule")
        return Decision(self.default, "no rule matched; default policy", "default")


def default_policy() -> Policy:
    """Reads are free; everything else needs a human."""
    return Policy((("read_*", Action.ALLOW), ("list_*", Action.ALLOW)), Action.ASK)


@dataclass(frozen=True)
class ApprovalRequest:
    call_id: str
    actor: str
    tool: str
    args: Mapping[str, Any]
    reason: str


Approver = Callable[[ApprovalRequest], bool]


def approve_all(_: ApprovalRequest) -> bool:
    return True


def deny_all(_: ApprovalRequest) -> bool:
    return False


@dataclass(frozen=True)
class Outcome:
    call_id: str
    status: str  # ok | denied | error
    text: str
    label: Label = PUBLIC
    decision: Decision | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class Broker:
    def __init__(
        self,
        authority: Authority,
        registry: ToolRegistry,
        journal: Journal,
        policy: Policy | None = None,
        *,
        approver: Approver = deny_all,
        clock: Callable[[], float] = time.time,
        flow_enforcement: bool = True,
    ) -> None:
        self.authority = authority
        self.registry = registry
        self.journal = journal
        self.policy = policy or default_policy()
        self.approver = approver
        self.clock = clock
        self.flow_enforcement = flow_enforcement  # False exists only for mutation tests
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._n = 0

    def call(
        self,
        token: Token,
        tool_name: str,
        args: Mapping[str, Any],
        ctx: Label = PUBLIC,
        actor: str = "agent",
    ) -> Outcome:
        with self._lock:
            self._n += 1
            call_id = f"c{self._n}"
        args = dict(args)
        j = self.journal
        j.append(
            "call_requested",
            {
                "call": call_id,
                "actor": actor,
                "tool": tool_name,
                "args": {k: clip(str(v)) for k, v in args.items()},
                "ctx": ctx.to_dict(),
            },
        )

        def refuse(decision: Decision) -> Outcome:
            j.append(
                "decision",
                {
                    "call": call_id,
                    "action": decision.action.value,
                    "reason": decision.reason,
                    "source": decision.source,
                },
            )
            text = f"Denied ({decision.source}): {decision.reason}"
            return Outcome(call_id, "denied", text, PUBLIC, decision)

        try:
            chain = self.authority.verify(token)
        except CapabilityError as exc:
            return refuse(Decision(Action.DENY, f"invalid token: {exc}", "capability"))
        tool = self.registry.get(tool_name)
        if tool is None:
            return refuse(Decision(Action.DENY, f"unknown tool '{tool_name}'", "unknown_tool"))

        with self._lock:  # check and reserve budget atomically, so parallel agents cannot overshoot
            check = evaluate(
                token.caveats,
                chain,
                tool.name,
                args,
                is_sink=tool.sink,
                now=self.clock(),
                counts=self._counts,
            )
            if check.ok:
                for key in check.counter_keys:
                    self._counts[key] = self._counts.get(key, 0) + 1
        if not check.ok:
            return refuse(Decision(Action.DENY, check.reason, "capability"))

        decision = self._flow(tool, args, ctx, self.policy.evaluate(tool))
        if decision.action is Action.DENY:
            return refuse(decision)
        j.append(
            "decision",
            {
                "call": call_id,
                "action": decision.action.value,
                "reason": decision.reason,
                "source": decision.source,
            },
        )
        if decision.action is Action.ASK:
            approved = self.approver(ApprovalRequest(call_id, actor, tool.name, args, decision.reason))
            j.append("approval", {"call": call_id, "approved": bool(approved)})
            if not approved:
                return Outcome(call_id, "denied", "Denied (human): the action was declined", PUBLIC, decision)

        try:
            text, status = str(tool.fn(**args)), "ok"
        except Exception as exc:
            text, status = f"{type(exc).__name__}: {exc}", "error"
        label = tool.label_for(args) if status == "ok" else PUBLIC
        j.append(
            "call_result",
            {"call": call_id, "status": status, "text": clip(text), "label": label.to_dict()},
        )
        return Outcome(call_id, status, text, label, decision)

    def _flow(self, tool: Tool, args: Mapping[str, Any], ctx: Label, decision: Decision) -> Decision:
        """Information-flow check. It can only tighten the decision, never loosen it."""
        if not (self.flow_enforcement and tool.sink):
            return decision
        clearance = tool.clear_for(args)
        if ANY not in clearance:
            leaked = ctx.conf - clearance
            if leaked:
                return Decision(
                    Action.DENY,
                    f"context carries {sorted(leaked)} that this destination is not cleared to receive",
                    "flow",
                )
        if ctx.untrusted and decision.action is Action.ALLOW:
            return Decision(
                Action.ASK,
                "context contains untrusted content; a human must review this outbound call",
                "flow",
            )
        return decision
