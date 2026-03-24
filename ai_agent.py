from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from utils.regex_utils import find_flag_candidates, is_likely_flag_candidate


SYSTEM_PROMPT = """You are an expert Capture The Flag (CTF) solver.
You must:

* Analyze the challenge and previous outputs
* Choose exactly ONE tool at a time
* Never guess the flag
* Only use available tools
* Stop when a valid flag is found

You must respond ONLY in JSON format:
{
"tool": "tool_name",
"confidence": 0.0,
"reason": "short explanation",
"params": { ... },
"alternatives": [
  {
    "tool": "backup_tool_name",
    "confidence": 0.0,
    "reason": "short explanation",
    "params": { ... }
  }
]
}
"""


TOOL_SPECS: dict[str, dict[str, str]] = {
    "submit_flag": {
        "name": "submit_flag",
        "description": "Submit a discovered flag candidate and end the solve when it is valid.",
        "when_to_use": "Use only when a concrete flag string is already present in prior outputs or preprocessing results.",
    },
    "read_file": {
        "name": "read_file",
        "description": "Read a UTF-8 text file from disk.",
        "when_to_use": "Use when a challenge artifact is likely a readable text file.",
    },
    "echo": {
        "name": "echo",
        "description": "Echo text into the tool history for inspection.",
        "when_to_use": "Use only as a weak fallback when no better analysis tool is available.",
    },
    "extract_strings": {
        "name": "extract_strings",
        "description": "Extract readable printable strings from a file.",
        "when_to_use": "Use for binaries, PDFs, or unknown files when text may be embedded inside.",
    },
    "extract_metadata": {
        "name": "extract_metadata",
        "description": "Extract metadata from PDFs and images.",
        "when_to_use": "Use for forensic document or image challenges where metadata may contain clues or flags.",
    },
    "decode_base64": {
        "name": "decode_base64",
        "description": "Safely validate and decode Base64 text.",
        "when_to_use": "Use when text strongly resembles Base64-encoded content.",
    },
    "decode_hex": {
        "name": "decode_hex",
        "description": "Safely validate and decode hexadecimal text.",
        "when_to_use": "Use when text looks hex-encoded and may decode into readable output.",
    },
    "xor_single_byte_bruteforce": {
        "name": "xor_single_byte_bruteforce",
        "description": "Try all 256 single-byte XOR keys and rank outputs by readability.",
        "when_to_use": "Use when a byte sequence appears to be single-byte XOR encoded.",
    },
    "file_magic_identification": {
        "name": "file_magic_identification",
        "description": "Detect likely file type from magic bytes.",
        "when_to_use": "Use when a file extension is missing, misleading, or unreliable.",
    },
    "repair_magic_bytes": {
        "name": "repair_magic_bytes",
        "description": "Repair known corrupted magic-byte patterns such as broken JPEG headers.",
        "when_to_use": "Use when file signatures look almost correct but the header bytes are corrupted.",
    },
    "extract_text_ocr": {
        "name": "extract_text_ocr",
        "description": "Extract readable text from an image using OCR.",
        "when_to_use": "Use after repairing or identifying an image when the flag may be visually embedded.",
    },
    "extract_flag_regex": {
        "name": "extract_flag_regex",
        "description": "Search text for common CTF flag patterns like picoCTF{...}.",
        "when_to_use": "Use after decoding or extraction when text may already contain a flag.",
    },
}


def _compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _collect_string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        collected: list[str] = []
        for item in value.values():
            collected.extend(_collect_string_values(item))
        return collected
    if isinstance(value, list):
        collected: list[str] = []
        for item in value:
            collected.extend(_collect_string_values(item))
        return collected
    return []


def _extract_output_text(previous_outputs: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for item in previous_outputs:
        chunks.extend(_collect_string_values(item))
    return "\n".join(chunks)


def get_tool_descriptions(available_tools: list[str]) -> list[dict[str, str]]:
    return [TOOL_SPECS[name] for name in available_tools if name in TOOL_SPECS]


def _build_user_prompt(context: dict[str, Any]) -> str:
    prompt_payload = {
        "challenge_description": context.get("challenge_description", ""),
        "previous_tool_outputs": context.get("previous_tool_outputs", []),
        "files_available": context.get("files_available", []),
        "preprocessing": context.get("preprocessing", {}),
        "available_tools": context.get("available_tools", []),
        "tool_descriptions": context.get("tool_descriptions", []),
        "failed_tools": context.get("failed_tools", []),
        "instructions": [
            "Choose exactly one tool for the next action.",
            "Use only tools from available_tools.",
            "If a valid flag is already present, use submit_flag.",
            "Provide a confidence score between 0.0 and 1.0.",
            "List ranked backup options in alternatives from next best to worst.",
            "Do not reuse a failed tool unless new evidence appears.",
            "Do not include any text outside the JSON object.",
        ],
    }
    return _compact_json(prompt_payload)


class LLMClient(Protocol):
    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        ...


@dataclass(slots=True)
class MockLLMClient:
    """Rule-based constrained planner used until a real LLM backend is attached."""

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        del system_prompt
        context = json.loads(user_prompt)

        available_tools = list(context.get("available_tools", []))
        available_set = set(available_tools)
        previous_outputs = context.get("previous_tool_outputs", [])
        files_available = context.get("files_available", [])
        challenge_description = context.get("challenge_description", "")
        preprocessing = context.get("preprocessing", {})
        failed_tools = set(context.get("failed_tools", []))

        searchable_text = "\n".join(
            part for part in [_extract_output_text(previous_outputs), "\n".join(_collect_string_values(preprocessing))] if part
        )
        candidates = find_flag_candidates(searchable_text)
        if candidates and "submit_flag" in available_set and "submit_flag" not in failed_tools:
            return _compact_json(
                {
                    "tool": "submit_flag",
                    "confidence": 0.98,
                    "reason": "A flag candidate was found in previous or preprocessed outputs.",
                    "params": {"flag": candidates[0]},
                    "alternatives": [],
                }
            )

        if files_available:
            primary_path = files_available[0]
            repaired_paths = [
                value
                for value in _collect_string_values(previous_outputs)
                if value.endswith(".jpg") or value.endswith(".jpeg") or value.endswith(".png")
            ]
            if repaired_paths and "extract_text_ocr" in available_set and "extract_text_ocr" not in failed_tools:
                return _compact_json(
                    {
                        "tool": "extract_text_ocr",
                        "confidence": 0.92,
                        "reason": "A repaired image artifact is available and OCR is the best next step to read visible text.",
                        "params": {"path": repaired_paths[-1]},
                        "alternatives": [
                            {
                                "tool": "extract_strings",
                                "confidence": 0.25,
                                "reason": "Fallback if OCR fails and the image still contains embedded text in raw bytes.",
                                "params": {"path": repaired_paths[-1]},
                            }
                        ]
                        if "extract_strings" in available_set and "extract_strings" not in failed_tools
                        else [],
                    }
                )

            if "JFIF" in searchable_text and "repair_magic_bytes" in available_set and "repair_magic_bytes" not in failed_tools:
                output_path = f"{primary_path}_repaired.jpg"
                return _compact_json(
                    {
                        "tool": "repair_magic_bytes",
                        "confidence": 0.93,
                        "reason": "The file contains JFIF markers but is not recognized as a valid image, suggesting a broken JPEG header.",
                        "params": {"path": primary_path, "output_path": output_path},
                        "alternatives": [
                            {
                                "tool": "file_magic_identification",
                                "confidence": 0.61,
                                "reason": "Confirm the signature mismatch before attempting repair.",
                                "params": {"path": primary_path},
                            }
                        ]
                        if "file_magic_identification" in available_set and "file_magic_identification" not in failed_tools
                        else [],
                    }
                )

            if "extract_metadata" in available_set and "extract_metadata" not in failed_tools:
                alternatives: list[dict[str, Any]] = []
                if "extract_strings" in available_set and "extract_strings" not in failed_tools:
                    alternatives.append(
                        {
                            "tool": "extract_strings",
                            "confidence": 0.76,
                            "reason": "If metadata is not useful, printable strings are the next best forensic check.",
                            "params": {"path": primary_path},
                        }
                    )
                if "read_file" in available_set and "read_file" not in failed_tools:
                    alternatives.append(
                        {
                            "tool": "read_file",
                            "confidence": 0.42,
                            "reason": "Fallback to direct file reading if the artifact is plain text.",
                            "params": {"path": primary_path},
                        }
                    )
                return _compact_json(
                    {
                        "tool": "extract_metadata",
                        "confidence": 0.85,
                        "reason": "Metadata is a strong first step for forensic documents and images.",
                        "params": {"path": primary_path},
                        "alternatives": alternatives,
                    }
                )

            if "extract_strings" in available_set and "extract_strings" not in failed_tools:
                return _compact_json(
                    {
                        "tool": "extract_strings",
                        "confidence": 0.74,
                        "reason": "Extract readable strings from the file to surface embedded clues.",
                        "params": {"path": primary_path},
                        "alternatives": [],
                    }
                )

        if challenge_description and "extract_flag_regex" in available_set and "extract_flag_regex" not in failed_tools:
            return _compact_json(
                {
                    "tool": "extract_flag_regex",
                    "confidence": 0.58,
                    "reason": "Check whether the current text already contains an exposed flag pattern.",
                    "params": {"text": challenge_description},
                    "alternatives": [
                        {
                            "tool": "decode_base64",
                            "confidence": 0.34,
                            "reason": "Fallback if the text resembles Base64-encoded content.",
                            "params": {"data": challenge_description},
                        }
                    ]
                    if "decode_base64" in available_set and "decode_base64" not in failed_tools
                    else [],
                }
            )

        if challenge_description and "echo" in available_set and "echo" not in failed_tools:
            return _compact_json(
                {
                    "tool": "echo",
                    "confidence": 0.15,
                    "reason": "Surface the challenge text in the history as a weak fallback.",
                    "params": {"text": challenge_description},
                    "alternatives": [],
                }
            )

        fallback_tool = next((tool for tool in available_tools if tool not in failed_tools), "submit_flag")
        return _compact_json(
            {
                "tool": fallback_tool,
                "confidence": 0.05,
                "reason": "No stronger action is available from the provided context.",
                "params": {},
                "alternatives": [],
            }
        )


def _validate_ranked_option(option: dict[str, Any], available_tools: list[str], *, label: str) -> dict[str, Any]:
    required_keys = {"tool", "confidence", "reason", "params"}
    missing = required_keys - option.keys()
    if missing:
        raise ValueError(f"{label} is missing required keys: {', '.join(sorted(missing))}")

    tool = option["tool"]
    confidence = option["confidence"]
    reason = option["reason"]
    params = option["params"]

    if not isinstance(tool, str) or tool not in available_tools:
        raise ValueError(f"{label} tool '{tool}' is not in available_tools.")
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise ValueError(f"{label} confidence must be between 0.0 and 1.0.")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(f"{label} reason must be a non-empty string.")
    if not isinstance(params, dict):
        raise ValueError(f"{label} params must be a JSON object.")

    if tool == "submit_flag":
        flag = params.get("flag")
        if not isinstance(flag, str) or not flag.strip():
            raise ValueError(f"{label} submit_flag requires params.flag to be a non-empty string.")
        if not is_likely_flag_candidate(flag):
            raise ValueError(f"{label} submit_flag candidate failed validation.")

    return {
        "tool": tool,
        "confidence": float(confidence),
        "reason": reason.strip(),
        "params": params,
    }


def _validate_action_schema(action: dict[str, Any], available_tools: list[str]) -> dict[str, Any]:
    if not isinstance(action, dict):
        raise ValueError("LLM response must decode to a JSON object.")

    primary = _validate_ranked_option(action, available_tools, label="Primary action")
    alternatives = action.get("alternatives", [])
    if not isinstance(alternatives, list):
        raise ValueError("The 'alternatives' field must be a list.")

    primary["alternatives"] = [
        _validate_ranked_option(option, available_tools, label=f"Alternative {index + 1}")
        for index, option in enumerate(alternatives)
    ]
    return primary


def get_next_action(
    context: dict[str, Any],
    llm_client: LLMClient | None = None,
) -> dict[str, Any]:
    """
    Expected context shape:
    {
        "challenge_description": str,
        "previous_tool_outputs": list[dict],
        "preprocessing": dict,
        "files_available": list[str],
        "available_tools": list[str],
        "tool_descriptions": list[dict],
        "failed_tools": list[str]
    }
    """

    llm = llm_client or MockLLMClient()

    available_tools = context.get("available_tools")
    if not isinstance(available_tools, list) or not available_tools:
        raise ValueError("context.available_tools must be a non-empty list.")

    user_prompt = _build_user_prompt(context)
    raw_response = llm.complete(system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt)

    try:
        action = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise ValueError("LLM response was not valid JSON.") from exc

    return _validate_action_schema(action, available_tools)


EXAMPLE_INPUT: dict[str, Any] = {
    "challenge_description": "We recovered a suspicious PDF and need to inspect it for hidden data.",
    "previous_tool_outputs": [],
    "preprocessing": {},
    "files_available": ["challenge.pdf"],
    "available_tools": ["extract_metadata", "extract_strings", "submit_flag", "read_file"],
    "tool_descriptions": get_tool_descriptions(
        ["extract_metadata", "extract_strings", "submit_flag", "read_file"]
    ),
    "failed_tools": [],
}


EXAMPLE_OUTPUT: dict[str, Any] = {
    "tool": "extract_metadata",
    "confidence": 0.85,
    "reason": "Metadata is a strong first step for forensic documents and images.",
    "params": {"path": "challenge.pdf"},
    "alternatives": [
        {
            "tool": "extract_strings",
            "confidence": 0.76,
            "reason": "If metadata is not useful, printable strings are the next best forensic check.",
            "params": {"path": "challenge.pdf"},
        }
    ],
}
