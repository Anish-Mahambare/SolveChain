from __future__ import annotations

import json
import logging
from typing import Any

from ai_agent import get_next_action, get_tool_descriptions
from preprocessing import run_preprocessing
from tools import TOOLS, execute_tool
from tools.echo_tool import EchoTool
from tools.read_file_tool import ReadFileTool
from tools.registry import ToolRegistry
from tools.submit_flag_tool import SubmitFlagTool
from utils.regex_utils import find_flag_candidates


LOGGER = logging.getLogger("ctf_solver")


def _setup_logger() -> None:
    if not LOGGER.handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def _serialize_output(output: dict[str, Any]) -> str:
    return json.dumps(output, ensure_ascii=True, sort_keys=True)


def _decode_history_output(output: str) -> Any:
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def _collect_text_fragments(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments: list[str] = []
        for item in value.values():
            fragments.extend(_collect_text_fragments(item))
        return fragments
    if isinstance(value, list):
        fragments: list[str] = []
        for item in value:
            fragments.extend(_collect_text_fragments(item))
        return fragments
    return []


def _build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register("echo", EchoTool())
    registry.register("read_file", ReadFileTool())
    registry.register("submit_flag", SubmitFlagTool())
    return registry


def _list_available_tools(tool_registry: ToolRegistry) -> list[str]:
    return sorted(set(tool_registry.list_tools()) | set(TOOLS))


def _extract_files_available(challenge_input: dict[str, Any]) -> list[str]:
    files_available = challenge_input.get("files_available", [])
    if not isinstance(files_available, list):
        raise ValueError("input.files_available must be a list when provided.")
    return [str(item) for item in files_available]


def _execute_selected_tool(tool_name: str, params: dict[str, Any], tool_registry: ToolRegistry) -> tuple[bool, dict[str, Any], str | None]:
    if tool_name in TOOLS:
        execution = execute_tool(tool_name, params)
        return execution["success"], execution["data"] or {}, execution["error"]

    try:
        tool = tool_registry.get(tool_name)
    except KeyError as exc:
        return False, {}, str(exc)

    try:
        output = tool(params)
    except Exception as exc:
        return False, {}, f"Tool '{tool_name}' execution failed: {exc}"

    success = isinstance(output, dict) and output.get("status") != "error"
    error = None if success else output.get("error", "Tool returned an error.") if isinstance(output, dict) else "Tool returned a non-dict result."
    return success, output if isinstance(output, dict) else {"result": output}, error


def solve_challenge(challenge_input: dict[str, Any]) -> dict[str, Any]:
    _setup_logger()

    challenge_description = str(challenge_input.get("challenge_description", "")).strip()
    max_steps = int(challenge_input.get("max_steps", 10))
    llm_client = challenge_input.get("llm_client")
    tool_registry = challenge_input.get("tool_registry") or _build_default_registry()
    files_available = _extract_files_available(challenge_input)
    memory = challenge_input.get("memory") or {"history": []}

    if not isinstance(memory, dict) or "history" not in memory or not isinstance(memory["history"], list):
        raise ValueError("input.memory must have the structure {'history': [...]} when provided.")
    if max_steps <= 0:
        raise ValueError("input.max_steps must be greater than zero.")

    available_tools = _list_available_tools(tool_registry)
    final_flag: str | None = None

    for step in range(1, max_steps + 1):
        context = {
            "challenge_description": challenge_description,
            "previous_tool_outputs": [
                {
                    "tool": item.get("tool", ""),
                    "output": _decode_history_output(str(item.get("output", ""))),
                }
                for item in memory["history"]
            ],
            "files_available": files_available,
            "available_tools": available_tools,
            "tool_descriptions": get_tool_descriptions(available_tools),
            "failed_tools": [],
        }
        context["preprocessing"] = run_preprocessing(context)
        LOGGER.info(
            "Step %s: preprocessing produced %s result(s)",
            step,
            len(context["preprocessing"].get("results", [])),
        )

        LOGGER.info("Step %s: requesting next action from AI agent", step)
        try:
            action = get_next_action(context, llm_client=llm_client)
        except ValueError as exc:
            error_message = f"AI agent returned invalid JSON or schema: {exc}"
            LOGGER.error("Step %s: %s", step, error_message)
            return {
                "status": "error",
                "reason": error_message,
                "steps_taken": step - 1,
                "memory": memory,
            }

        ranked_actions = [action, *action.get("alternatives", [])]
        output: dict[str, Any] | None = None
        selected_tool_name: str | None = None
        selected_error: str | None = None
        selected_candidate: dict[str, Any] | None = None
        failed_attempts: list[dict[str, Any]] = []

        for candidate in ranked_actions:
            LOGGER.info(
                "Step %s: trying tool=%s confidence=%.2f params=%s",
                step,
                candidate["tool"],
                candidate["confidence"],
                candidate["params"],
            )
            success, candidate_output, error = _execute_selected_tool(candidate["tool"], candidate["params"], tool_registry)
            if success:
                output = candidate_output
                selected_tool_name = candidate["tool"]
                selected_candidate = candidate
                selected_error = None
                break

            context["failed_tools"].append(candidate["tool"])
            selected_error = error
            failed_attempts.append(
                {
                    "tool": candidate["tool"],
                    "reason": candidate["reason"],
                    "confidence": candidate["confidence"],
                    "params": candidate["params"],
                    "error": error,
                }
            )
            LOGGER.warning(
                "Step %s: tool=%s failed, trying next ranked option: %s",
                step,
                candidate["tool"],
                error,
            )

        if output is None or selected_tool_name is None:
            return {
                "status": "error",
                "reason": selected_error or "All ranked tool options failed.",
                "steps_taken": step - 1,
                "memory": memory,
            }

        memory["history"].append(
            {
                "tool": selected_tool_name,
                "reason": selected_candidate["reason"] if selected_candidate else "",
                "confidence": selected_candidate["confidence"] if selected_candidate else None,
                "params": selected_candidate["params"] if selected_candidate else {},
                "failed_attempts": failed_attempts,
                "output": _serialize_output(output),
            }
        )
        LOGGER.info("Step %s: tool output=%s", step, memory["history"][-1]["output"])

        if selected_tool_name == "submit_flag" and output.get("status") == "ok":
            final_flag = str(output.get("flag", "")).strip()
            LOGGER.info("Step %s: valid flag submitted, stopping loop", step)
            return {
                "status": "success",
                "flag_found": True,
                "flag": final_flag,
                "steps_taken": step,
                "memory": memory,
            }

        decoded_output = _decode_history_output(memory["history"][-1]["output"])
        candidates = find_flag_candidates("\n".join(_collect_text_fragments(decoded_output)))
        if candidates:
            LOGGER.info("Step %s: flag candidate observed in tool output: %s", step, candidates[0])

    LOGGER.warning("Maximum step count reached without finding a flag")
    return {
        "status": "max_steps_reached",
        "flag_found": False,
        "flag": final_flag,
        "steps_taken": max_steps,
        "memory": memory,
    }


if __name__ == "__main__":
    example_input = {
        "challenge_description": "Inspect the provided note and submit the flag if found.",
        "files_available": ["example_flag.txt"],
        "max_steps": 5,
    }
    print(json.dumps(solve_challenge(example_input), indent=2))
