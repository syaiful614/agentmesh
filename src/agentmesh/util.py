"""Small helpers."""

from __future__ import annotations


def clip(text: str, limit: int = 200) -> str:
    """Shorten text for journal entries (full data never needs to live in the audit log)."""
    return text if len(text) <= limit else text[: limit - 3] + "..."
