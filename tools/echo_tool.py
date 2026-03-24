from __future__ import annotations

from tools.base import BaseTool, ToolInput, ToolOutput


class EchoTool(BaseTool):
    """Simple example tool stub used to validate orchestration wiring."""

    name = "echo"
    description = "Returns the provided text payload."

    def __call__(self, input_data: ToolInput) -> ToolOutput:
        text = str(input_data.get("text", ""))
        return {
            "status": "ok",
            "tool": self.name,
            "echo": text,
        }

