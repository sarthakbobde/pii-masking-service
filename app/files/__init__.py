"""Files in, the same file type out: picks the handler from the extension and checks the content matches it."""
import io
import zipfile

from app.files.pdf import UnsupportedFile
from app.redact import Redactor

MEDIA = {
    "txt": "text/plain; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
ALIASES = {"markdown": "md", "text": "txt", "log": "txt"}
OOXML_MAIN = {"docx": "word/document.xml", "pptx": "ppt/presentation.xml", "xlsx": "xl/workbook.xml"}
MAX_ZIP_RATIO = 100             # refuse archives that expand more than this (zip bombs)


def kind_of(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    ext = ALIASES.get(ext, ext)
    if ext not in MEDIA:
        raise UnsupportedFile(f"Unsupported file type '.{ext}'. Supported: " + ", ".join("." + k for k in MEDIA) + ".")
    return ext


def decode(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8-sig"
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16"), "utf-16"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), "cp1252"


def encode(text: str, enc: str) -> bytes:
    if enc == "utf-8-sig":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    return text.encode(enc, errors="replace")


def _check(kind: str, data: bytes) -> None:
    if kind == "pdf":
        if b"%PDF-" not in data[:1024]:
            raise UnsupportedFile("The file is not a PDF.")
    elif kind in OOXML_MAIN:
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise UnsupportedFile(f"The file is not a valid .{kind} file.") from None
        if OOXML_MAIN[kind] not in set(z.namelist()):
            raise UnsupportedFile(f"The file is not a valid .{kind} file.")
        if sum(i.file_size for i in z.infolist()) > max(len(data), 1) * MAX_ZIP_RATIO:
            raise UnsupportedFile("The file expands to far more than its size; refused.")
    elif b"\x00" in data[:4096] and data[:2] not in (b"\xff\xfe", b"\xfe\xff"):
        raise UnsupportedFile("The file is not text.")


def preview_text(kind: str, data: bytes, limit: int = 8000) -> tuple[str, bool]:
    """The readable text of a (masked) file, cut at `limit` characters, for the admin page's document check."""
    try:
        if kind in ("txt", "md", "csv"):
            text = decode(data)[0]
        elif kind == "pdf":
            import pymupdf
            with pymupdf.open(stream=data, filetype="pdf") as doc:
                text = "\n\n".join(page.get_text() for page in doc)
        elif kind == "docx":
            import docx
            d = docx.Document(io.BytesIO(data))
            cells = [c.text for t in d.tables for row in t.rows for c in row.cells]
            text = "\n".join([p.text for p in d.paragraphs] + cells)
        elif kind == "pptx":
            import pptx
            prs = pptx.Presentation(io.BytesIO(data))
            text = "\n".join(sh.text_frame.text for s in prs.slides for sh in s.shapes if sh.has_text_frame)
        else:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True)
            text = "\n".join(" | ".join("" if c is None else str(c) for c in row)
                             for ws in wb.worksheets for row in ws.iter_rows(values_only=True))
    except Exception:
        return "", False
    text = "\n".join(line for line in (ln.rstrip() for ln in text.splitlines()) if line)
    return text[:limit], len(text) > limit


def process(filename: str, data: bytes, r: Redactor) -> tuple[bytes, str, dict]:
    """(new file bytes, media type, extra details such as the PDF's OCR pages)."""
    from app.files import ooxml, pdf, sheet
    kind = kind_of(filename)
    _check(kind, data)
    extra: dict = {"file_type": kind}
    if kind in ("txt", "md"):
        text, enc = decode(data)
        out = encode(r.run(text)[0], enc)
    elif kind == "csv":
        out = sheet.csv_bytes(data, r, decode, encode)
    elif kind == "docx":
        out = ooxml.docx(data, r)
    elif kind == "pptx":
        out = ooxml.pptx(data, r)
    elif kind == "xlsx":
        out = sheet.xlsx(data, r)
    else:
        out, info = pdf.pdf(data, r)
        extra.update(info)
    return out, MEDIA[kind], extra
