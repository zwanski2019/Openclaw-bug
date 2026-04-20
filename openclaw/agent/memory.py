"""Agent memory. Short-term = in-process deque. Long-term = DB.

Used to inject context into planner/analyzer prompts so the agent
remembers what it's tried and what worked.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from openclaw.db import client as db


@dataclass
class ShortTermMemory:
    """Per-run working memory. Stays in process."""
    max_size: int = 50
    items: deque = field(default_factory=lambda: deque(maxlen=50))

    def __post_init__(self):
        self.items = deque(maxlen=self.max_size)

    def remember(self, entry: dict) -> None:
        self.items.append(entry)

    def to_context(self) -> str:
        lines = []
        for i, item in enumerate(self.items, 1):
            lines.append(f"{i}. [{item.get('kind')}] {item.get('summary')}")
        return "\n".join(lines)


class LongTermMemory:
    """Persists across runs. Keyed by target scope."""

    def __init__(self, scope: str = "global") -> None:
        self.scope = scope

    def remember(self, kind: str, content: str) -> None:
        db.add_memory(self.scope, kind, content)

    def recall(self, kind: str | None = None, limit: int = 20) -> list[dict]:
        return db.recall_memory(self.scope, kind, limit)

    def lessons(self) -> list[str]:
        return [m["content"] for m in self.recall("lesson", limit=20)]

    def dedup_keys(self) -> set[str]:
        """Keys that mark findings already submitted / known duplicates."""
        return {m["content"] for m in self.recall("dedup_key", limit=1000)}
