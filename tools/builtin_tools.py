from __future__ import annotations

import base64
import binascii
import string
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools.base import ToolInput, ToolOutput
from utils.regex_utils import find_flag_candidates, is_likely_flag_candidate


def _success(tool: str, **extra: Any) -> ToolOutput:
    return {"status": "ok", "tool": tool, **extra}


def _error(tool: str, message: str, **extra: Any) -> ToolOutput:
    return {"status": "error", "tool": tool, "error": message, **extra}


def _read_bytes_from_path(path: str) -> bytes:
    return Path(path).read_bytes()


def _coerce_bytes(data: str, input_format: str = "utf-8") -> bytes:
    if input_format == "utf-8":
        return data.encode("utf-8")
    if input_format == "hex":
        return bytes.fromhex(data)
    if input_format == "base64":
        normalized = data.strip()
        padding = (-len(normalized)) % 4
        if padding:
            normalized += "=" * padding
        return base64.b64decode(normalized, validate=True)
    raise ValueError(f"Unsupported input_format: {input_format}")


def _decode_bytes_preview(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    return {
        "decoded_text": text,
        "decoded_hex": raw.hex(),
        "length": len(raw),
    }


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    printable_bytes = sum(chr(byte) in string.printable for byte in raw)
    return printable_bytes / len(raw)


def _xor_candidate_score(text: str, printable_ratio: float) -> tuple[float, int, int, int]:
    ascii_letters = sum(ch in string.ascii_letters for ch in text)
    digits = sum(ch.isdigit() for ch in text)
    likely_flags = find_flag_candidates(text)
    exact_flag_bonus = 0
    if likely_flags and any(is_likely_flag_candidate(candidate) for candidate in likely_flags):
        exact_flag_bonus = 1000

    ctf_hint_bonus = 0
    if "{" in text and "}" in text:
        ctf_hint_bonus += 50
    if "_" in text:
        ctf_hint_bonus += 10
    if "picoCTF{" in text or "flag{" in text:
        ctf_hint_bonus += 200

    return (
        exact_flag_bonus + ctf_hint_bonus + printable_ratio * 100,
        ascii_letters,
        digits,
        -sum(ch == "\ufffd" for ch in text),
    )


def extract_strings(input_data: ToolInput) -> ToolOutput:
    tool = "extract_strings"
    path = str(input_data.get("path", "")).strip()
    min_length = int(input_data.get("min_length", 4))
    encoding = str(input_data.get("encoding", "latin-1"))

    if not path:
        return _error(tool, "Missing required parameter: path")
    if min_length <= 0:
        return _error(tool, "min_length must be greater than zero", min_length=min_length)

    try:
        raw = _read_bytes_from_path(path)
    except FileNotFoundError:
        return _error(tool, "File not found", path=path)

    chars: list[str] = []
    strings_found: list[str] = []
    for byte in raw:
        char = bytes([byte]).decode(encoding, errors="ignore")
        if char and char in string.printable and char not in "\x0b\x0c\r":
            chars.append(char)
            continue
        if len(chars) >= min_length:
            strings_found.append("".join(chars))
        chars = []

    if len(chars) >= min_length:
        strings_found.append("".join(chars))

    return _success(tool, path=path, min_length=min_length, strings=strings_found, count=len(strings_found))


def extract_metadata(input_data: ToolInput) -> ToolOutput:
    tool = "extract_metadata"
    path = str(input_data.get("path", "")).strip()
    if not path:
        return _error(tool, "Missing required parameter: path")

    file_path = Path(path)
    if not file_path.exists():
        return _error(tool, "File not found", path=path)

    suffix = file_path.suffix.lower()
    if suffix == ".pdf":
        try:
            from PyPDF2 import PdfReader
        except ImportError:
            return _error(tool, "PyPDF2 is not installed", path=path)

        try:
            reader = PdfReader(str(file_path))
            metadata = {str(key): str(value) for key, value in (reader.metadata or {}).items()}
            return _success(tool, path=path, file_type="pdf", metadata=metadata)
        except Exception as exc:
            return _error(tool, f"Failed to read PDF metadata: {exc}", path=path)

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return _error(tool, "Pillow is not installed", path=path)

    try:
        with Image.open(file_path) as image:
            metadata: dict[str, Any] = {str(key): str(value) for key, value in image.info.items()}
            exif = image.getexif()
            if exif:
                for key, value in exif.items():
                    metadata[TAGS.get(key, str(key))] = str(value)
            metadata["format"] = str(image.format)
            metadata["mode"] = str(image.mode)
            metadata["size"] = f"{image.width}x{image.height}"
            return _success(tool, path=path, file_type="image", metadata=metadata)
    except Exception as exc:
        return _error(tool, f"Failed to read image metadata: {exc}", path=path)


def decode_base64(input_data: ToolInput) -> ToolOutput:
    tool = "decode_base64"
    data = str(input_data.get("data", "")).strip()
    if not data:
        return _error(tool, "Missing required parameter: data")

    compact = "".join(data.split())
    if len(compact) < 4:
        return _error(tool, "Input is too short to be valid base64")

    try:
        normalized = compact + ("=" * ((4 - len(compact) % 4) % 4))
        decoded = base64.b64decode(normalized, validate=True)
    except binascii.Error:
        return _error(tool, "Input is not valid base64", data=data)

    return _success(tool, input=data, **_decode_bytes_preview(decoded))


def decode_hex(input_data: ToolInput) -> ToolOutput:
    tool = "decode_hex"
    data = str(input_data.get("data", "")).strip()
    if not data:
        return _error(tool, "Missing required parameter: data")

    normalized = data.replace(" ", "")
    if normalized.startswith("0x"):
        normalized = normalized[2:]

    try:
        decoded = bytes.fromhex(normalized)
    except ValueError:
        return _error(tool, "Input is not valid hexadecimal", data=data)

    return _success(tool, input=data, **_decode_bytes_preview(decoded))


def xor_single_byte_bruteforce(input_data: ToolInput) -> ToolOutput:
    tool = "xor_single_byte_bruteforce"
    data = str(input_data.get("data", "")).strip()
    input_format = str(input_data.get("input_format", "hex")).strip().lower()
    top_n = int(input_data.get("top_n", 10))

    if not data:
        return _error(tool, "Missing required parameter: data")
    if top_n <= 0:
        return _error(tool, "top_n must be greater than zero", top_n=top_n)

    try:
        raw = _coerce_bytes(data, input_format=input_format)
    except (ValueError, binascii.Error) as exc:
        return _error(tool, f"Invalid input for xor bruteforce: {exc}", input_format=input_format)

    ranked: list[dict[str, Any]] = []
    for key in range(256):
        candidate = bytes(byte ^ key for byte in raw)
        decoded_text = candidate.decode("utf-8", errors="replace")
        printable_ratio = round(_printable_ratio(candidate), 4)
        ranked.append(
            {
                "key": key,
                "key_hex": f"0x{key:02x}",
                "printable_ratio": printable_ratio,
                "decoded_text": decoded_text,
                "decoded_hex": candidate.hex(),
                "score": _xor_candidate_score(decoded_text, printable_ratio),
            }
        )

    ranked.sort(key=lambda item: item["score"], reverse=True)
    for item in ranked:
        item.pop("score", None)
    return _success(tool, input_format=input_format, candidates=ranked[:top_n], total_keys_tested=256)


def file_magic_identification(input_data: ToolInput) -> ToolOutput:
    tool = "file_magic_identification"
    path = str(input_data.get("path", "")).strip()
    if not path:
        return _error(tool, "Missing required parameter: path")

    try:
        header = _read_bytes_from_path(path)[:16]
    except FileNotFoundError:
        return _error(tool, "File not found", path=path)

    signatures = [
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07\x00", "RAR archive"),
        (b"\x1f\x8b\x08", "Gzip archive"),
        (b"\x7fELF", "ELF binary"),
        (b"MZ", "PE executable"),
    ]

    detected_type = "unknown"
    for signature, description in signatures:
        if header.startswith(signature):
            detected_type = description
            break

    return _success(tool, path=path, detected_type=detected_type, magic_bytes=header.hex())


def repair_magic_bytes(input_data: ToolInput) -> ToolOutput:
    tool = "repair_magic_bytes"
    path = str(input_data.get("path", "")).strip()
    output_path = str(input_data.get("output_path", "")).strip()
    if not path:
        return _error(tool, "Missing required parameter: path")

    source = Path(path)
    if not source.exists():
        return _error(tool, "File not found", path=path)

    raw = source.read_bytes()
    repaired = raw
    repaired_type = "unknown"
    bytes_changed: list[dict[str, Any]] = []

    if len(raw) >= 10 and raw.startswith(b"\\x\xff\xe0") and raw[6:10] == b"JFIF":
        repaired = b"\xff\xd8" + raw[2:]
        repaired_type = "JPEG image"
        bytes_changed = [
            {"offset": 0, "original_hex": f"{raw[0]:02x}", "new_hex": "ff"},
            {"offset": 1, "original_hex": f"{raw[1]:02x}", "new_hex": "d8"},
        ]

    if repaired == raw:
        return _error(tool, "No known corruption pattern detected", path=path)

    target = Path(output_path) if output_path else source.with_name(f"{source.stem}_repaired{source.suffix or '.bin'}")
    target.write_bytes(repaired)

    return _success(
        tool,
        path=path,
        repaired_path=str(target),
        repaired_type=repaired_type,
        bytes_changed=bytes_changed,
    )


def extract_text_ocr(input_data: ToolInput) -> ToolOutput:
    tool = "extract_text_ocr"
    path = str(input_data.get("path", "")).strip()
    if not path:
        return _error(tool, "Missing required parameter: path")

    source = Path(path)
    if not source.exists():
        return _error(tool, "File not found", path=path)

    resized_image_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="ctf_ocr_img_", suffix=source.suffix or ".png", delete=False) as image_handle:
            resized_image_path = Path(image_handle.name)
        resize = subprocess.run(
            ["sips", "-Z", "3200", str(source), "--out", str(resized_image_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        ocr_input = resized_image_path if resize.returncode == 0 else source

        with tempfile.NamedTemporaryFile(prefix="ctf_ocr_", suffix=".txt", delete=False) as handle:
            output_base = Path(handle.name).with_suffix("")
        command = [
            "tesseract",
            str(ocr_input),
            str(output_base),
            "--psm",
            "7",
            "-c",
            "tessedit_char_whitelist=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        if resized_image_path is not None:
            resized_image_path.unlink(missing_ok=True)
        return _error(tool, "tesseract is not installed or not on PATH", path=path)

    output_file = output_base.with_suffix(".txt")
    stderr = completed.stderr.strip()
    if completed.returncode != 0:
        if resized_image_path is not None:
            resized_image_path.unlink(missing_ok=True)
        if output_file.exists():
            output_file.unlink()
        return _error(tool, "OCR extraction failed", path=path, stderr=stderr)

    extracted_text = output_file.read_text(encoding="utf-8", errors="replace")
    output_file.unlink(missing_ok=True)
    if resized_image_path is not None:
        resized_image_path.unlink(missing_ok=True)
    return _success(tool, path=path, extracted_text=extracted_text, flags=find_flag_candidates(extracted_text))


def extract_flag_regex(input_data: ToolInput) -> ToolOutput:
    tool = "extract_flag_regex"
    text = str(input_data.get("text", ""))
    if not text:
        return _error(tool, "Missing required parameter: text")

    flags = find_flag_candidates(text)
    return _success(tool, flags=flags, count=len(flags))


TOOLS = {
    "extract_strings": extract_strings,
    "extract_metadata": extract_metadata,
    "decode_base64": decode_base64,
    "decode_hex": decode_hex,
    "xor_single_byte_bruteforce": xor_single_byte_bruteforce,
    "file_magic_identification": file_magic_identification,
    "repair_magic_bytes": repair_magic_bytes,
    "extract_text_ocr": extract_text_ocr,
    "extract_flag_regex": extract_flag_regex,
}
