from __future__ import annotations

from pathlib import Path

from tools.base import BaseTool, ToolInput, ToolOutput


class ReadFileTool(BaseTool):
    """Reads UTF-8 text content from a file path."""

    name = "read_file"
    description = "Read a UTF-8 text file from disk."

    def __call__(self, input_data: ToolInput) -> ToolOutput:
        path = str(input_data.get("path", "")).strip()
        if not path:
            return {
                "status": "error",
                "tool": self.name,
                "error": "Missing required parameter: path",
            }

        try:
            content = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            return {
                "status": "error",
                "tool": self.name,
                "path": path,
                "error": "File not found",
            }
        except UnicodeDecodeError:
            return {
                "status": "error",
                "tool": self.name,
                "path": path,
                "error": "File is not valid UTF-8 text",
            }

        return {
            "status": "ok",
            "tool": self.name,
            "path": path,
            "content": content,
        }

