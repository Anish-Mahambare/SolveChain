from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from PIL import Image, ImageDraw, ImageFont
from PyPDF2 import PdfWriter

from tools.builtin_tools import (
    decode_base64,
    decode_hex,
    extract_flag_regex,
    extract_metadata,
    extract_strings,
    extract_text_ocr,
    file_magic_identification,
    repair_magic_bytes,
    xor_single_byte_bruteforce,
)
from tools.echo_tool import EchoTool
from tools.read_file_tool import ReadFileTool
from tools.submit_flag_tool import SubmitFlagTool


def _load_font() -> ImageFont.ImageFont | ImageFont.FreeTypeFont:
    for candidate in [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Courier New Bold.ttf",
    ]:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, 90)
    return ImageFont.load_default()


class ToolScenarioTests(unittest.TestCase):
    def test_tools_in_ctf_scenarios(self) -> None:
        with TemporaryDirectory(dir=".") as tmp:
            tmpdir = Path(tmp)

            text_file = tmpdir / "note.txt"
            text_file.write_text("clue line\nflag{tool_read_success}\n", encoding="utf-8")

            binary_file = tmpdir / "embedded.bin"
            binary_file.write_bytes(b"\x00\x01noiseFLAGxxflag{strings_hidden}\x02tail")

            pdf_path = tmpdir / "meta.pdf"
            writer = PdfWriter()
            writer.add_blank_page(width=200, height=200)
            writer.add_metadata(
                {
                    "/Author": base64.b64encode(b"picoCTF{meta_decode}").decode(),
                    "/Title": "forensics",
                }
            )
            with pdf_path.open("wb") as handle:
                writer.write(handle)

            image_path = tmpdir / "ocr.png"
            image = Image.new("RGB", (2200, 500), "white")
            draw = ImageDraw.Draw(image)
            draw.text((60, 170), "picoCTF{ocr_tool_flag}", fill="black", font=_load_font())
            image.save(image_path)

            clean_jpg_path = tmpdir / "clean.jpg"
            Image.new("RGB", (800, 250), "white").save(clean_jpg_path, format="JPEG")
            raw_jpg = clean_jpg_path.read_bytes()
            corrupt_jpg_path = tmpdir / "broken_jfif.bin"
            corrupt_jpg_path.write_bytes(b"\\x" + raw_jpg[2:])

            echo_result = EchoTool()({"text": "flag{echo_history}"})
            self.assertEqual(echo_result["echo"], "flag{echo_history}")

            read_result = ReadFileTool()({"path": str(text_file)})
            self.assertIn("flag{tool_read_success}", read_result["content"])

            submit_result = SubmitFlagTool()({"flag": "flag{tool_submit_success}"})
            self.assertTrue(submit_result["submitted"])

            strings_result = extract_strings({"path": str(binary_file), "min_length": 4})
            joined_strings = "\n".join(strings_result["strings"])
            self.assertIn("flag{strings_hidden}", joined_strings)

            metadata_result = extract_metadata({"path": str(pdf_path)})
            self.assertEqual(metadata_result["metadata"]["/Author"], base64.b64encode(b"picoCTF{meta_decode}").decode())

            base64_result = decode_base64({"data": base64.b64encode(b"picoCTF{base64_tool}").decode()})
            self.assertEqual(base64_result["decoded_text"], "picoCTF{base64_tool}")

            hex_result = decode_hex({"data": "7069636f4354467b6865785f746f6f6c7d"})
            self.assertEqual(hex_result["decoded_text"], "picoCTF{hex_tool}")

            xor_secret = b"picoCTF{xor_single_byte}"
            xor_key = 0x13
            xor_ciphertext = bytes(byte ^ xor_key for byte in xor_secret).hex()
            xor_result = xor_single_byte_bruteforce({"data": xor_ciphertext, "input_format": "hex", "top_n": 5})
            top_texts = [candidate["decoded_text"] for candidate in xor_result["candidates"]]
            self.assertIn("picoCTF{xor_single_byte}", top_texts)

            magic_result = file_magic_identification({"path": str(pdf_path)})
            self.assertEqual(magic_result["detected_type"], "PDF document")

            repaired_path = tmpdir / "repaired.jpg"
            repair_result = repair_magic_bytes({"path": str(corrupt_jpg_path), "output_path": str(repaired_path)})
            self.assertEqual(repair_result["status"], "ok")
            self.assertTrue(repaired_path.exists())

            ocr_result = extract_text_ocr({"path": str(image_path)})
            self.assertIn("picoCTF{ocr_tool_flag}", ocr_result["flags"])

            regex_result = extract_flag_regex({"text": "noise picoCTF{regex_tool} more noise flag{shortish_valid} end"})
            self.assertIn("picoCTF{regex_tool}", regex_result["flags"])


if __name__ == "__main__":
    unittest.main()
