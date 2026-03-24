from __future__ import annotations

import io
import json
import logging
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from solver import solve_challenge


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "web"


def _decode_output(raw_output: str) -> Any:
    try:
        return json.loads(raw_output)
    except json.JSONDecodeError:
        return raw_output


def _format_result(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2)
    return str(value)


@contextmanager
def _capture_solver_logs() -> Any:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))

    root_logger = logging.getLogger()
    previous_level = root_logger.level
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)
    try:
        yield stream
    finally:
        root_logger.removeHandler(handler)
        root_logger.setLevel(previous_level)


def run_solver_session(description: str, file_path: str | None = None, max_steps: int = 10) -> dict[str, Any]:
    challenge_input = {
        "challenge_description": description,
        "files_available": [file_path] if file_path else [],
        "max_steps": max_steps,
    }

    with _capture_solver_logs() as log_stream:
        result = solve_challenge(challenge_input)

    history = result.get("memory", {}).get("history", [])
    steps = [
        {
            "index": index,
            "tool": item.get("tool", "<unknown>"),
            "reason": item.get("reason", ""),
            "confidence": item.get("confidence"),
            "params": item.get("params", {}),
            "failed_attempts": item.get("failed_attempts", []),
            "decoded_output": _decode_output(str(item.get("output", ""))),
            "rendered_output": _format_result(_decode_output(str(item.get("output", "")))),
        }
        for index, item in enumerate(history, start=1)
    ]

    flag = result.get("flag")
    return {
        "description": description,
        "file_path": file_path,
        "max_steps": max_steps,
        "summary": {
            "status": result.get("status"),
            "steps_taken": result.get("steps_taken"),
            "flag_found": bool(flag),
            "flag": flag,
            "reason": result.get("reason"),
        },
        "logs": [line for line in log_stream.getvalue().splitlines() if line.strip()],
        "steps": steps,
        "raw_result": result,
    }


class SolveChainHandler(BaseHTTPRequestHandler):
    server_version = "SolveChainWeb/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_static_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if parsed.path == "/app.css":
            self._serve_static_file(STATIC_DIR / "app.css", "text/css; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._serve_static_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return
        if parsed.path == "/api/health":
            self._send_json({"status": "ok"})
            return

        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/solve":
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            payload = self._read_json_body()
            description = str(payload.get("description", "")).strip()
            file_path = str(payload.get("file_path", "")).strip() or None
            max_steps = int(payload.get("max_steps", 10))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": f"Invalid request payload: {exc}"}, status=HTTPStatus.BAD_REQUEST)
            return

        if not description:
            self._send_json({"error": "description is required"}, status=HTTPStatus.BAD_REQUEST)
            return

        if max_steps <= 0:
            self._send_json({"error": "max_steps must be greater than zero"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            response = run_solver_session(description, file_path=file_path, max_steps=max_steps)
        except Exception as exc:
            self._send_json({"error": f"Solver execution failed: {exc}"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self._send_json(response)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b"{}"
        body = json.loads(raw_body.decode("utf-8"))
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")
        return body

    def _serve_static_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def serve(*, host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), SolveChainHandler)
    print(f"SolveChain web app running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
