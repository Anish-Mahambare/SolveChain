from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable


ToolInput = dict[str, Any]
ToolOutput = dict[str, Any]


@runtime_checkable
class ToolCallable(Protocol):
    """Callable signature shared by all tools."""

    def __call__(self, input_data: ToolInput) -> ToolOutput:
        ...


class BaseTool(ABC):
    """Abstract base class for class-based tool implementations."""

    name: str
    description: str

    @abstractmethod
    def __call__(self, input_data: ToolInput) -> ToolOutput:
        raise NotImplementedError

