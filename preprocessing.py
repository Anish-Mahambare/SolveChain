from __future__ import annotations

import re
from typing import Any

from tools import execute_tool
from utils.regex_utils import reconstruct_fragmented_flags


BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=\s]+$")
HEX_PATTERN = re.compile(r"^(?:0x)?[0-9a-fA-F\s]+$")


def _looks_like_base64(text: str) -> bool:
    compact = "".join(text.split())
    if len(compact) < 8 or len(compact) % 4 != 0:
        return False
    return bool(BASE64_PATTERN.fullmatch(text))


def _looks_like_hex(text: str) -> bool:
    compact = text.replace(" ", "")
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if len(compact) < 6 or len(compact) % 2 != 0:
        return False
    return bool(HEX_PATTERN.fullmatch(text))


def _preprocess_text(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    if _looks_like_base64(text):
        decoded = execute_tool("decode_base64", {"data": text})
        if decoded["success"]:
            results.append(
                {
                    "kind": "text_base64_decode",
                    "source": text,
                    "result": decoded["data"],
                }
            )

    if _looks_like_hex(text):
        decoded = execute_tool("decode_hex", {"data": text})
        if decoded["success"]:
            results.append(
                {
                    "kind": "text_hex_decode",
                    "source": text,
                    "result": decoded["data"],
                }
            )

    for candidate in reconstruct_fragmented_flags(text):
        results.append(
            {
                "kind": "reconstructed_flag_fragments",
                "source": text,
                "result": {
                    "status": "ok",
                    "tool": "fragment_reconstruction",
                    "flag": candidate,
                },
            }
        )

    return results


def _collect_string_fragments(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        fragments: list[str] = []
        for item in value.values():
            fragments.extend(_collect_string_fragments(item))
        return fragments
    if isinstance(value, list):
        fragments: list[str] = []
        for item in value:
            fragments.extend(_collect_string_fragments(item))
        return fragments
    return []


def _preprocess_nested_strings(value: Any) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for fragment in _collect_string_fragments(value):
        if fragment in seen:
            continue
        seen.add(fragment)
        results.extend(_preprocess_text(fragment))
    return results


def _preprocess_file(path: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    magic = execute_tool("file_magic_identification", {"path": path})
    if magic["success"]:
        magic_result = {
            "kind": "file_magic_identification",
            "source": path,
            "result": magic["data"],
        }
        results.append(magic_result)
        results.extend(_preprocess_nested_strings(magic_result))

    metadata = execute_tool("extract_metadata", {"path": path})
    if metadata["success"]:
        metadata_result = {
            "kind": "file_metadata",
            "source": path,
            "result": metadata["data"],
        }
        results.append(metadata_result)
        results.extend(_preprocess_nested_strings(metadata_result))

    strings = execute_tool("extract_strings", {"path": path})
    if strings["success"]:
        strings_result = {
            "kind": "file_strings",
            "source": path,
            "result": strings["data"],
        }
        results.append(strings_result)
        results.extend(_preprocess_nested_strings(strings_result))

    return results


def run_preprocessing(context: dict[str, Any]) -> dict[str, Any]:
    """
    Run lightweight preprocessing before AI reasoning.

    Returns:
    {
      "results": [...]
    }
    """

    challenge_description = str(context.get("challenge_description", "")).strip()
    files_available = context.get("files_available", [])
    previous_tool_outputs = context.get("previous_tool_outputs", [])

    results: list[dict[str, Any]] = []

    if challenge_description:
        results.extend(_preprocess_text(challenge_description))

    for item in previous_tool_outputs:
        output = item.get("output")
        results.extend(_preprocess_nested_strings(output))

    for file_path in files_available:
        results.extend(_preprocess_file(str(file_path)))

    return {"results": results}
