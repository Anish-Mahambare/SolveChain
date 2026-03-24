from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol


EXPLANATION_SYSTEM_PROMPT = """You explain completed CTF solves for humans.
Write a concise human-readable explanation that covers:

* why each tool was chosen
* what each step discovered
* how the final flag was identified

Do not solve the challenge again. Explain only from the provided solve trace.
"""


def _compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


class ExplanationLLMClient(Protocol):
    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        ...


@dataclass(slots=True)
class MockExplanationLLMClient:
    """Deterministic explainer used until a real explanation model is attached."""

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        del system_prompt
        payload = json.loads(user_prompt)
        description = payload.get("challenge_description", "")
        history = payload.get("history", [])
        final_flag = payload.get("final_flag")

        lines: list[str] = []
        lines.append(f"Challenge summary: {description}")

        for index, step in enumerate(history, start=1):
            tool = step.get("tool", "<unknown>")
            reason = step.get("reason", "No reason recorded.")
            output = step.get("decoded_output", {})
            discovery = "It did not reveal a useful clue."

            if isinstance(output, dict):
                if tool == "submit_flag" and output.get("flag"):
                    discovery = f"It submitted the recovered flag `{output['flag']}`."
                elif output.get("metadata"):
                    discovery = f"It extracted metadata: {output['metadata']}."
                elif output.get("strings"):
                    discovery = f"It extracted readable strings and found {len(output.get('strings', []))} string block(s)."
                elif output.get("decoded_text"):
                    discovery = f"It decoded the content into `{output['decoded_text']}`."
                elif output.get("flags"):
                    discovery = f"It found flag candidates: {output['flags']}."
                elif output.get("echo"):
                    discovery = f"It surfaced the text `{output['echo']}`."

            lines.append(f"Step {index}: `{tool}` was chosen because {reason} {discovery}")

            failed_attempts = step.get("failed_attempts", [])
            for failed in failed_attempts:
                lines.append(
                    f"Step {index} fallback: `{failed.get('tool')}` was attempted but failed with: {failed.get('error')}."
                )

        if final_flag:
            lines.append(f"Final result: the flag was identified as `{final_flag}`.")
        else:
            lines.append("Final result: no flag was confirmed.")

        return "\n".join(lines)


def _decode_history_output(raw_output: str) -> Any:
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        return raw_output


def generate_explanation(
    challenge_description: str,
    solve_result: dict[str, Any],
    llm_client: ExplanationLLMClient | None = None,
) -> str:
    llm = llm_client or MockExplanationLLMClient()

    history = solve_result.get("memory", {}).get("history", [])
    payload = {
        "challenge_description": challenge_description,
        "status": solve_result.get("status"),
        "final_flag": solve_result.get("flag"),
        "history": [
            {
                **step,
                "decoded_output": _decode_history_output(str(step.get("output", ""))),
            }
            for step in history
        ],
    }

    return llm.complete(
        system_prompt=EXPLANATION_SYSTEM_PROMPT,
        user_prompt=_compact_json(payload),
    )


if __name__ == "__main__":
    from solver import solve_challenge

    description = "Find the flag hidden in the metadata of this PDF."
    result = solve_challenge(
        {
            "challenge_description": description,
            "files_available": ["fixtures/forensics/hidden_flag_metadata.pdf"],
            "max_steps": 5,
        }
    )
    print(generate_explanation(description, result))
