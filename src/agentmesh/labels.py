"""Information-flow labels.

Every piece of data an agent has seen is summarised by a Label:

* ``conf``      the confidentiality tags of data it has read (for example ``{"notes"}``);
* ``untrusted`` whether attacker-controllable content has entered its context.

Labels only ever grow (join = union). An agent's *context label* is the join of everything it
has read, plus everything its sub-agents returned to it. That last part is the point: a
sub-agent cannot launder data into a "clean" string, because the label travels with the result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Label:
    conf: frozenset[str] = frozenset()
    untrusted: bool = False

    def join(self, other: Label) -> Label:
        return Label(self.conf | other.conf, self.untrusted or other.untrusted)

    __or__ = join

    @property
    def is_clean(self) -> bool:
        return not self.conf and not self.untrusted

    def to_dict(self) -> dict[str, Any]:
        return {"conf": sorted(self.conf), "untrusted": self.untrusted}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Label:
        return cls(frozenset(data.get("conf", [])), bool(data.get("untrusted", False)))


PUBLIC = Label()
UNTRUSTED = Label(untrusted=True)


def private(*tags: str) -> Label:
    return Label(frozenset(tags))
