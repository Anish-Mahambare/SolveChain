from __future__ import annotations

from tools.base import BaseTool, ToolInput, ToolOutput
from utils.regex_utils import is_likely_flag_candidate


class SubmitFlagTool(BaseTool):
    """Marks a candidate flag as submitted."""

    name = "submit_flag"
    description = "Submit a discovered flag candidate."

    def __call__(self, input_data: ToolInput) -> ToolOutput:
        flag = str(input_data.get("flag", "")).strip()
        if not flag:
            return {
                "status": "error",
                "tool": self.name,
                "error": "Missing required parameter: flag",
            }

        if not is_likely_flag_candidate(flag):
            return {
                "status": "error",
                "tool": self.name,
                "error": "Flag candidate failed validation.",
                "flag": flag,
            }

        return {
            "status": "ok",
            "tool": self.name,
            "submitted": True,
            "flag": flag,
        }
