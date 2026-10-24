"""Tools carry the facts the security layer reasons about: what they return and where they send."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .labels import PUBLIC, Label

ANY = "*"  # a clearance containing ANY accepts every confidentiality tag (a fully internal sink)


def _no_clearance(_: Mapping[str, Any]) -> frozenset[str]:
    return frozenset()


@dataclass(frozen=True)
class Tool:
    name: str
    fn: Callable[..., str]
    description: str = ""
    produces: Label | Callable[[Mapping[str, Any]], Label] = PUBLIC
    sink: bool = False  # sends information out of the trust boundary
    clearance: Callable[[Mapping[str, Any]], frozenset[str]] = _no_clearance
    mutates: bool = False

    def label_for(self, args: Mapping[str, Any]) -> Label:
        return self.produces(args) if callable(self.produces) else self.produces

    def clear_for(self, args: Mapping[str, Any]) -> frozenset[str]:
        return self.clearance(args)


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool '{tool.name}'")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    @property
    def names(self) -> list[str]:
        return sorted(self._tools)
