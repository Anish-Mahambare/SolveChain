from __future__ import annotations

import re


STRICT_FLAG_PATTERNS = [
    re.compile(r"\bpicoCTF\{[A-Za-z0-9_@!\-]+\}"),
    re.compile(r"\bflag\{[A-Za-z0-9_@!\-]{6,}\}"),
]
FLAG_FRAGMENT_PATTERNS = [
    re.compile(r"\b(?:FLAGPART|FLAG_FRAGMENT|FRAGMENT|PART)\b\s*[:=]\s*([A-Za-z0-9_@!\-{}]+)", re.IGNORECASE),
    re.compile(r"\b(?:flag\s+part|flag\s+fragment)\b\s*[:=]\s*([A-Za-z0-9_@!\-{}]+)", re.IGNORECASE),
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


def reconstruct_fragmented_flags(text: str) -> list[str]:
    """
    Reassemble flags from repeated line fragments such as:
    `INFO FLAGPART: picoCTF{us3_`
    `INFO FLAGPART: y0urlinux_`
    ...
    """

    unique_fragments: list[str] = []
    seen_fragments: set[str] = set()

    for line in text.splitlines():
        for pattern in FLAG_FRAGMENT_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            fragment = match.group(1).strip()
            if fragment and fragment not in seen_fragments:
                unique_fragments.append(fragment)
                seen_fragments.add(fragment)
            break

    reconstructed: list[str] = []
    if unique_fragments:
        candidate = "".join(unique_fragments)
        if is_likely_flag_candidate(candidate):
            reconstructed.append(candidate)

    return reconstructed
