from __future__ import annotations

from pathlib import Path

from PyPDF2 import PdfWriter


def create_sample_pdf(output_path: str) -> None:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    writer.add_metadata(
        {
            "/Title": "Forensic PDF Challenge",
            "/Author": "Codex Test Harness",
            "/Subject": "picoCTF{pdf_metadata_hidden_flag}",
            "/Keywords": "forensics,pdf,metadata,ctf",
        }
    )

    with target.open("wb") as handle:
        writer.write(handle)


if __name__ == "__main__":
    create_sample_pdf("fixtures/forensics/hidden_flag_metadata.pdf")
