"""Append-only, hash-chained audit journal (SQLite)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Any

GENESIS = "0" * 64


def _hash(prev: str, seq: int, kind: str, data: str, ts: float) -> str:
    return hashlib.sha256(f"{prev}|{seq}|{kind}|{data}|{ts!r}".encode()).hexdigest()


class Journal:
    def __init__(self, path: str = ":memory:", clock: Callable[[], float] = time.time) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, ts REAL NOT NULL,"
            " kind TEXT NOT NULL, data TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)"
        )
        self._db.commit()
        row = self._db.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        self._seq: int = row[0] if row else 0
        self._head: str = row[1] if row else GENESIS

    @property
    def head(self) -> str:
        return self._head

    def append(self, kind: str, data: dict[str, Any]) -> int:
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        with self._lock:
            seq = self._seq + 1
            ts = self._clock()
            digest = _hash(self._head, seq, kind, payload, ts)
            self._db.execute(
                "INSERT INTO events (seq, ts, kind, data, prev, hash) VALUES (?,?,?,?,?,?)",
                (seq, ts, kind, payload, self._head, digest),
            )
            self._db.commit()
            self._seq, self._head = seq, digest
            return seq

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT seq, ts, kind, data, hash FROM events ORDER BY seq").fetchall()
        out = [{"seq": s, "ts": t, "kind": k, "data": json.loads(d), "hash": h} for s, t, k, d, h in rows]
        return [e for e in out if kind is None or e["kind"] == kind]

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the chain. Returns (ok, first_bad_seq). Tail truncation is not detectable."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, ts, kind, data, prev, hash FROM events ORDER BY seq"
            ).fetchall()
        prev, expected_seq = GENESIS, 1
        for seq, ts, kind, data, stored_prev, stored_hash in rows:
            if seq != expected_seq or stored_prev != prev:
                return False, seq
            if _hash(prev, seq, kind, data, ts) != stored_hash:
                return False, seq
            prev, expected_seq = stored_hash, expected_seq + 1
        return True, None

    def close(self) -> None:
        self._db.close()
