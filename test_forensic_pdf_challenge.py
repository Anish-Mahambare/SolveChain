from __future__ import annotations

import json

from ai_agent import get_next_action
from preprocessing import run_preprocessing
from solver import solve_challenge


def main() -> None:
    challenge_input = {
        "challenge_description": "Find the flag hidden in the metadata of this PDF.",
        "files_available": ["fixtures/forensics/hidden_flag_metadata.pdf"],
        "max_steps": 5,
    }

    initial_context = {
        "challenge_description": challenge_input["challenge_description"],
        "previous_tool_outputs": [],
        "files_available": challenge_input["files_available"],
        "available_tools": ["echo", "read_file", "submit_flag"],
    }
    initial_context["preprocessing"] = run_preprocessing(initial_context)
    initial_action = get_next_action(initial_context)

    print("=== Challenge ===")
    print(challenge_input["challenge_description"])
    print()

    print("=== Preprocessing Results ===")
    print(json.dumps(initial_context["preprocessing"], indent=2))
    print()

    print("=== Step 1 AI Decision ===")
    print(json.dumps(initial_action, indent=2))
    print()

    print("=== Solver Run ===")
    result = solve_challenge(challenge_input)
    print(json.dumps(result, indent=2))
    print()

    print("=== Step-by-Step Tool Outputs ===")
    for index, item in enumerate(result["memory"]["history"], start=1):
        print(f"Step {index}: tool={item['tool']}")
        print(item["output"])
        print()

    print("=== Final Flag ===")
    print(result.get("flag"))


if __name__ == "__main__":
    main()
