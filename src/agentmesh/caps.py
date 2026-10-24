"""Capability tokens with attenuation (macaroon-style).

A token is ``(id, caveats, sig)`` where the signature is an HMAC chain::

    sig0 = HMAC(root_key, id)
    sig_i = HMAC(sig_{i-1}, canonical_json(caveat_i))

Anyone holding a token can *append* a caveat (it only needs the current signature), so a parent
agent can hand a child a strictly weaker token without contacting the authority. Nobody can
*remove* a caveat without the root key, because the chain would no longer verify. Every caveat
must hold for a call to be admitted, so authority can only shrink as it is delegated.

Caveat types:
  tools      {"allow": [globs]}                         tool name must match one of the globs
  args       {"tool": glob, "arg": name, "regex": re}   argument must be present and match
  max_calls  {"n": int}                                 calls admitted under this exact chain prefix
  expires    {"at": epoch seconds}
  no_sinks   {}                                         tools that send data out are refused
  depth      {"remaining": int}                         how many more levels may be delegated
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

CAVEAT_TYPES = {"tools", "args", "max_calls", "expires", "no_sinks", "depth"}


class CapabilityError(Exception):
    """A token or caveat is invalid."""


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def validate_caveat(c: Any) -> None:
    if not isinstance(c, Mapping) or c.get("type") not in CAVEAT_TYPES:
        raise CapabilityError(f"unknown caveat {c!r}")
    kind = c["type"]
    if kind == "tools":
        allow = c.get("allow")
        if not isinstance(allow, list) or not allow or not all(isinstance(g, str) for g in allow):
            raise CapabilityError("'tools' caveat needs a non-empty list 'allow'")
    elif kind == "args":
        if not all(isinstance(c.get(k), str) for k in ("tool", "arg", "regex")):
            raise CapabilityError("'args' caveat needs string 'tool', 'arg' and 'regex'")
        try:
            re.compile(c["regex"])
        except re.error as exc:
            raise CapabilityError(f"'args' caveat has an invalid regex: {exc}") from exc
    elif kind in ("max_calls", "depth"):
        key = "n" if kind == "max_calls" else "remaining"
        value = c.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CapabilityError(f"'{kind}' caveat needs a non-negative integer '{key}'")
    elif kind == "expires":
        at = c.get("at")
        if isinstance(at, bool) or not isinstance(at, (int, float)):
            raise CapabilityError("'expires' caveat needs a numeric 'at'")


@dataclass(frozen=True, eq=False)
class Token:
    id: str
    caveats: tuple[Mapping[str, Any], ...]
    sig: str

    def attenuate(self, *caveats: Mapping[str, Any]) -> Token:
        """Return a strictly weaker token. Needs no key."""
        sig = bytes.fromhex(self.sig)
        added: list[Mapping[str, Any]] = []
        for caveat in caveats:
            validate_caveat(caveat)
            plain = dict(caveat)
            sig = _mac(sig, _canon(plain))
            added.append(plain)
        return Token(self.id, self.caveats + tuple(added), sig.hex())

    def encode(self) -> str:
        raw = _canon({"id": self.id, "caveats": list(self.caveats), "sig": self.sig})
        return base64.urlsafe_b64encode(raw).decode()

    @classmethod
    def decode(cls, text: str) -> Token:
        try:
            data = json.loads(base64.urlsafe_b64decode(text.encode()))
            return cls(str(data["id"]), tuple(data["caveats"]), str(data["sig"]))
        except (ValueError, KeyError, TypeError) as exc:
            raise CapabilityError(f"malformed token: {exc}") from exc


class Authority:
    """Holds the root key: mints tokens and verifies any token derived from them."""

    def __init__(self, root_key: bytes) -> None:
        if len(root_key) < 16:
            raise CapabilityError("root key must be at least 16 bytes")
        self._key = root_key

    def mint(self, token_id: str, *caveats: Mapping[str, Any]) -> Token:
        base = Token(token_id, (), _mac(self._key, token_id.encode()).hex())
        return base.attenuate(*caveats)

    def verify(self, token: Token) -> list[str]:
        """Return the signature after each caveat (a unique key per chain prefix)."""
        try:
            sig = _mac(self._key, token.id.encode())
            chain: list[str] = []
            for caveat in token.caveats:
                validate_caveat(caveat)
                sig = _mac(sig, _canon(dict(caveat)))
                chain.append(sig.hex())
            ok = hmac.compare_digest(sig.hex(), token.sig)
        except (AttributeError, TypeError) as exc:
            raise CapabilityError("not a token") from exc
        if not ok:
            raise CapabilityError("signature mismatch (token was altered or not issued here)")
        return chain


@dataclass
class CaveatCheck:
    ok: bool
    reason: str = ""
    counter_keys: list[str] = field(default_factory=list)


def evaluate(
    caveats: tuple[Mapping[str, Any], ...],
    chain: list[str],
    tool_name: str,
    args: Mapping[str, Any],
    *,
    is_sink: bool,
    now: float,
    counts: Mapping[str, int],
) -> CaveatCheck:
    keys: list[str] = []
    for i, c in enumerate(caveats):
        kind = c["type"]
        if kind == "tools":
            if not any(fnmatchcase(tool_name, g) for g in c["allow"]):
                return CaveatCheck(False, f"tool '{tool_name}' is outside the delegated scope")
        elif kind == "args":
            if fnmatchcase(tool_name, c["tool"]) and (
                c["arg"] not in args or not re.search(c["regex"], str(args[c["arg"]]))
            ):
                return CaveatCheck(False, f"argument '{c['arg']}' violates a delegated constraint")
        elif kind == "max_calls":
            if counts.get(chain[i], 0) >= c["n"]:
                return CaveatCheck(False, f"call budget of {c['n']} is exhausted")
            keys.append(chain[i])
        elif kind == "expires":
            if now >= c["at"]:
                return CaveatCheck(False, "token has expired")
        elif kind == "no_sinks" and is_sink:
            return CaveatCheck(False, f"'{tool_name}' sends data out and this token forbids that")
    return CaveatCheck(True, counter_keys=keys)


def remaining_depth(caveats: tuple[Mapping[str, Any], ...]) -> int | None:
    values = [c["remaining"] for c in caveats if c["type"] == "depth"]
    return min(values) if values else None


def scope_allows(caveats: tuple[Mapping[str, Any], ...], tool_name: str) -> bool:
    """Does the token's tool scope admit this tool? Used to show a model only what it may call."""
    return all(any(fnmatchcase(tool_name, g) for g in c["allow"]) for c in caveats if c["type"] == "tools")
