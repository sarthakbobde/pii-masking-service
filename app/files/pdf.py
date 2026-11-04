"""PDF: true redaction with PyMuPDF.

For each text block we rebuild its text from the words on the page, find what to replace, and add a redaction
annotation over the words concerned, carrying the label or token as its overlay text. Applying the redactions removes
those characters from the page's content stream (and blanks image pixels underneath): the value is gone from the file,
not hidden under a box. Whole words are redacted, so punctuation stuck to a value ("(john@x.com)") goes with it.

Scanned pages (images with next to no text) are read with OCR when Tesseract language data is available and OCR is
switched on; the image pixels under each value are blanked. Without OCR they are reported as unprocessed.
Also: links over redacted areas are removed; metadata, XMP, attachments, JavaScript and thumbnails are scrubbed.
Not covered: personal data inside images on pages that also have real text, form-field values, and annotations' text.
Encrypted PDFs are refused. Tokenised PDFs cannot be unmasked (the original text is gone).
"""
import logging
import os

from app.config import config
from app.redact import Redactor

log = logging.getLogger(__name__)
FONT = "helv"
MIN_TEXT = 20             # a page with images and fewer characters than this is treated as scanned
OCR_DPI = 300


class UnsupportedFile(ValueError):
    pass


def tessdata() -> str | None:
    """Where Tesseract's language data is, or None when OCR is unavailable."""
    import pymupdf
    if config.tessdata_dir:
        return config.tessdata_dir if os.path.isdir(config.tessdata_dir) else None
    try:
        return pymupdf.get_tessdata()
    except Exception:
        return None


def _fontsize(text: str, rect) -> float:
    import pymupdf
    width = pymupdf.get_text_length(text, fontname=FONT, fontsize=1) or 1
    return max(2.0, min(rect.height * 0.8, (rect.width - 0.5) / width, 12.0))


def _blocks(words) -> list[tuple[str, list]]:
    """[(block text, [(start, end, rect)])]: the words of each block joined by single spaces."""
    import pymupdf
    by_block: dict = {}
    for w in words:
        by_block.setdefault(w[5], []).append(w)
    out = []
    for _, ws in sorted(by_block.items()):
        ws.sort(key=lambda w: (w[6], w[7]))
        parts, spans, pos = [], [], 0
        for w in ws:
            if parts:
                pos += 1
            spans.append((pos, pos + len(w[4]), pymupdf.Rect(w[:4]), w[6]))
            parts.append(w[4])
            pos += len(w[4])
        out.append((" ".join(parts), spans))
    return out


def _redact_words(page, words, r: Redactor) -> list:
    import pymupdf
    rects = []
    for text, spans in _blocks(words):
        for c in r.find(text):
            lines: dict = {}
            for a, b, rect, line in spans:
                if a < c.end and c.start < b:
                    lines[line] = lines[line] | rect if line in lines else pymupdf.Rect(rect)
            for i, rect in enumerate(lines.values()):
                label = c.replacement if i == 0 else ""
                page.add_redact_annot(rect, text=label or None, fontname=FONT,
                                      fontsize=_fontsize(label, rect) if label else 11,
                                      fill=(1, 1, 1), text_color=(0, 0, 0), cross_out=False)
                rects.append(rect)
    return rects


def pdf(data: bytes, r: Redactor) -> tuple[bytes, dict]:
    import pymupdf
    if r.mode == "unmask":
        raise UnsupportedFile("A PDF cannot be unmasked: its original text was removed when it was tokenised.")
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception:
        raise UnsupportedFile("The file is not a readable PDF.") from None
    if doc.needs_pass or doc.is_encrypted:
        raise UnsupportedFile("Encrypted PDFs are not supported. Remove the password first.")
    data_dir = tessdata() if r.policy.ocr_enabled else None
    ocr_pages, unprocessed = [], []
    for page in doc:
        words = page.get_text("words")
        scanned = bool(page.get_images(full=True)) and sum(len(w[4]) for w in words) < MIN_TEXT
        if scanned:
            if not data_dir:
                unprocessed.append(page.number + 1)
                continue
            tp = page.get_textpage_ocr(language=r.policy.ocr_language, dpi=OCR_DPI, full=True, tessdata=data_dir)
            words = page.get_text("words", textpage=tp)
            ocr_pages.append(page.number + 1)
        rects = _redact_words(page, words, r)
        if rects:
            for link in page.get_links():
                if any(pymupdf.Rect(link["from"]).intersects(x) for x in rects):
                    page.delete_link(link)
            page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_PIXELS, graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                                  text=pymupdf.PDF_REDACT_TEXT_REMOVE)
    doc.scrub(attached_files=True, embedded_files=True, javascript=True, metadata=r.scrub, xml_metadata=r.scrub, thumbnails=True,
              reset_responses=True, clean_pages=False, hidden_text=False, redactions=False, remove_links=False, reset_fields=False)
    if r.scrub:
        doc.set_metadata({})
    pages = doc.page_count
    out = doc.tobytes(garbage=4, deflate=True)
    doc.close()
    return out, {"pages": pages, "ocr_pages": ocr_pages, "unprocessed_image_pages": unprocessed,
                 "ocr_available": data_dir is not None}
