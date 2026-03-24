from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from tools.builtin_tools import TOOLS


LOGGER = logging.getLogger("ctf_tool_engine")
WORKSPACE_ROOT = Path.cwd().resolve()
BLOCKED_PARAM_KEYS = {"cmd", "command", "shell", "script", "executable"}
PATH_PARAM_KEYS = {"path", "file", "filepath", "filename", "output_path"}


def _setup_logger() -> None:
    if not LOGGER.handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def _is_safe_path(path_value: str) -> bool:
    candidate = Path(path_value).expanduser()
    if candidate.is_absolute():
        try:
            candidate.resolve().relative_to(WORKSPACE_ROOT)
        except ValueError:
            return False
        return True

    normalized_parts = [part for part in candidate.parts if part not in ("", ".")]
    return ".." not in normalized_parts


def _validate_params(params: dict[str, Any]) -> str | None:
    for key, value in params.items():
        lowered_key = key.lower()

        if lowered_key in BLOCKED_PARAM_KEYS:
            return f"Parameter '{key}' is not allowed."

        if lowered_key in PATH_PARAM_KEYS and isinstance(value, str) and value.strip():
            if not _is_safe_path(value.strip()):
                return f"Unsafe path rejected for parameter '{key}'."

    return None


def execute_tool(tool_name: str, params: dict[str, Any]) -> dict[str, Any]:
    """
    Execute a registered tool and normalize the result shape.

    Returns:
    {
      "success": bool,
      "data": dict | None,
      "error": str | None
    }
    """

    _setup_logger()

    if not isinstance(tool_name, str) or not tool_name.strip():
        return {
            "success": False,
            "data": None,
            "error": "tool_name must be a non-empty string.",
        }

    if not isinstance(params, dict):
        return {
            "success": False,
            "data": None,
            "error": "params must be a dictionary.",
        }

    normalized_name = tool_name.strip()
    if normalized_name not in TOOLS:
        LOGGER.warning("Rejected unknown tool: %s", normalized_name)
        return {
            "success": False,
            "data": None,
            "error": f"Unknown tool: {normalized_name}",
        }

    validation_error = _validate_params(params)
    if validation_error:
        LOGGER.warning("Blocked unsafe execution for tool=%s reason=%s", normalized_name, validation_error)
        return {
            "success": False,
            "data": None,
            "error": validation_error,
        }

    tool = TOOLS[normalized_name]
    LOGGER.info("Executing tool=%s params=%s", normalized_name, params)

    try:
        result = tool(params)
    except Exception as exc:
        LOGGER.exception("Tool execution failed for %s", normalized_name)
        return {
            "success": False,
            "data": None,
            "error": f"Execution failed: {exc}",
        }

    is_success = isinstance(result, dict) and result.get("status") != "error"
    LOGGER.info("Completed tool=%s success=%s", normalized_name, is_success)
    return {
        "success": is_success,
        "data": result,
        "error": None if is_success else result.get("error", "Tool returned an error.") if isinstance(result, dict) else "Tool returned a non-dict result.",
    }
