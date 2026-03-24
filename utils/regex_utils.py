from __future__ import annotations

import re


STRICT_FLAG_PATTERNS = [
    re.compile(r"\bpicoCTF\{[A-Za-z0-9_@!\-]+\}"),
    re.compile(r"\bflag\{[A-Za-z0-9_@!\-]{6,}\}"),
]


def is_likely_flag_candidate(candidate: str) -> bool:
    text = candidate.strip()
    if len(text) < 12 or len(text) > 200:
        return False

    return any(pattern.fullmatch(text) for pattern in STRICT_FLAG_PATTERNS)


def find_flag_candidates(text: str) -> list[str]:
    """
    Extract simple CTF-style flag candidates such as `flag{...}`.

    Expand these patterns later to support challenge-specific formats.
    """

    broad_pattern = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9_]+?\{[^{}\n]+\})")
    candidates = broad_pattern.findall(text)
    filtered: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        if is_likely_flag_candidate(candidate):
            filtered.append(candidate)
            seen.add(candidate)
    return filtered
