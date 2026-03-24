from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from solver import solve_challenge
from webapp import serve


def _build_solve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-powered CTF solver CLI")
    parser.add_argument(
        "description",
        help="Challenge description to send into the solver.",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        help="Optional challenge file path.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=10,
        help="Maximum number of solver iterations. Default: 10.",
    )
    parser.add_argument(
        "--save-logs",
        dest="log_path",
        help="Optional path to save the full solver result as JSON.",
    )
    return parser


def _build_serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SolveChain browser frontend")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface for the web app. Default: 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for the web app. Default: 8000.",
    )
    return parser


def _decode_output(raw_output: str) -> Any:
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        return raw_output


def _format_result(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps(value, indent=2)
    if isinstance(value, list):
        return json.dumps(value, indent=2)
    return str(value)


def _print_steps(result: dict[str, Any]) -> None:
    history = result.get("memory", {}).get("history", [])
    if not history:
        print("No tool steps were recorded.")
        return

    for index, item in enumerate(history, start=1):
        print(f"Step {index}: Tool used -> {item.get('tool', '<unknown>')}")
        print(f"Step {index}: Result")
        print(_format_result(_decode_output(str(item.get("output", "")))))
        print()


def _save_logs(log_path: str, result: dict[str, Any]) -> None:
    target = Path(log_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2), encoding="utf-8")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        args = _build_serve_parser().parse_args(sys.argv[2:])
        serve(host=args.host, port=args.port)
        return

    solve_argv = sys.argv[2:] if len(sys.argv) > 1 and sys.argv[1] == "solve" else sys.argv[1:]
    args = _build_solve_parser().parse_args(solve_argv)

    challenge_input = {
        "challenge_description": args.description,
        "files_available": [args.file_path] if args.file_path else [],
        "max_steps": args.max_steps,
    }

    result = solve_challenge(challenge_input)

    print("=== Solver Summary ===")
    print(f"Status: {result.get('status')}")
    print(f"Steps taken: {result.get('steps_taken')}")
    print()

    print("=== Steps ===")
    _print_steps(result)

    flag = result.get("flag")
    print("=== Final Flag ===")
    if flag:
        print(f"FLAG: {flag}")
    else:
        print("No flag found.")

    if args.log_path:
        _save_logs(args.log_path, result)
        print()
        print(f"Saved logs to: {args.log_path}")


if __name__ == "__main__":
    main()
