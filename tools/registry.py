from __future__ import annotations

from typing import Iterable

from tools.base import ToolCallable


class ToolRegistry:
    """Stores and resolves tools by name."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolCallable] = {}

    def register(self, name: str, tool: ToolCallable) -> None:
        self._tools[name] = tool

    def bulk_register(self, tools: Iterable[tuple[str, ToolCallable]]) -> None:
        for name, tool in tools:
            self.register(name, tool)

    def get(self, name: str) -> ToolCallable:
        if name not in self._tools:
            available = ", ".join(sorted(self._tools)) or "<none>"
            raise KeyError(f"Tool '{name}' is not registered. Available tools: {available}")
        return self._tools[name]

    def list_tools(self) -> list[str]:
        return sorted(self._tools)

