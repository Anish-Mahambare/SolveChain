from __future__ import annotations

from pathlib import Path


def read_text_file(path: str) -> str:
    """Read a UTF-8 text file from disk."""

    return Path(path).read_text(encoding="utf-8")


def write_text_file(path: str, content: str) -> None:
    """Write UTF-8 text content to disk, creating parent directories if needed."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")

