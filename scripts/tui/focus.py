from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FocusState:
    items: list[str] = field(default_factory=list)
    index: int = 0

    @property
    def current(self) -> str:
        if not self.items:
            return ""
        self.index = max(0, min(self.index, len(self.items) - 1))
        return self.items[self.index]

    def set_items(self, items: list[str], preferred: str | None = None) -> None:
        old = self.current
        self.items = items
        if not items:
            self.index = 0
            return
        if preferred and preferred in items:
            self.index = items.index(preferred)
            return
        if old and old in items:
            self.index = items.index(old)
            return
        self.index = min(self.index, len(items) - 1)

    def next(self) -> None:
        if not self.items:
            return
        self.index = (self.index + 1) % len(self.items)

    def prev(self) -> None:
        if not self.items:
            return
        self.index = (self.index - 1) % len(self.items)
