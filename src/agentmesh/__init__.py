"""AgentMesh: capability-secure multi-agent runtime with cross-agent information-flow control."""

from ._version import __version__
from .broker import (
    Action,
    ApprovalRequest,
    Broker,
    Decision,
    Outcome,
    Policy,
    approve_all,
    default_policy,
    deny_all,
)
from .caps import Authority, CapabilityError, Token
from .journal import Journal
from .labels import PUBLIC, UNTRUSTED, Label, private
from .mesh import AgentResult, AgentView, Call, Delegate, Mesh, Observation, Parallel
from .tools import ANY, Tool, ToolRegistry

__all__ = [
    "ANY",
    "PUBLIC",
    "UNTRUSTED",
    "Action",
    "AgentResult",
    "AgentView",
    "ApprovalRequest",
    "Authority",
    "Broker",
    "Call",
    "CapabilityError",
    "Decision",
    "Delegate",
    "Journal",
    "Label",
    "Mesh",
    "Observation",
    "Outcome",
    "Parallel",
    "Policy",
    "Token",
    "Tool",
    "ToolRegistry",
    "__version__",
    "approve_all",
    "default_policy",
    "deny_all",
    "private",
]
