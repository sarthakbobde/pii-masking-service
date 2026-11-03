"""Word (.docx) and PowerPoint (.pptx): replace personal data paragraph by paragraph, keeping the formatting.

A paragraph's text is spread over runs (each with its own formatting). We read the paragraph as one string, find what
to replace, then edit the runs: the replacement goes into the run where the value starts and the rest of the value is
removed from the following runs, so formatting stays except inside a value that changed format part-way.

Covered: Word body, tables, text boxes, headers, footers, footnotes, endnotes and comments; PowerPoint slides (shapes,
tables, groups), speaker notes. Not covered: text inside charts, SmartArt diagrams, embedded objects and images.
Document properties (author, last modified by, title, subject, keywords, comments) are cleared.

Tables follow the spreadsheet rules: a cell that is just a keyword ("Home address") makes the next cell in its row
sensitive, and a keyword in the first row makes the cells below it sensitive. Such a cell is replaced whole.
"""
import io

from app.detect import KEYWORD_SCORE
from app.files.sheet import sensitive_cells
from app.policy import KEYWORD_TYPE
from app.redact import Change, Redactor

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

WORD = {"p": W + "p", "t": W + "t", "seps": {W + "tab": "\t", W + "br": "\n", W + "cr": "\n"},
        "tbl": W + "tbl", "tr": W + "tr", "tc": W + "tc"}
SLIDE = {"p": A + "p", "t": A + "t", "seps": {A + "br": "\n"}, "tbl": A + "tbl", "tr": A + "tr", "tc": A + "tc"}


def _segments(p, spec) -> list:
    """[(element or None, text)] of a paragraph in document order, without descending into nested paragraphs."""
    out = []

    def walk(el):
        for child in el:
            tag = child.tag
            if tag == spec["p"]:
                continue                                  # a paragraph inside a text box: handled on its own
            if tag == spec["t"]:
                out.append((child, child.text or ""))
            elif tag in spec["seps"]:
                out.append((None, spec["seps"][tag]))
            else:
                walk(child)
    walk(p)
    return out


def _text(p, spec) -> str:
    return "".join(t for _, t in _segments(p, spec))


def _whole_cells(root, spec, keywords) -> set:
    """Paragraphs of table cells that are sensitive because of a keyword beside or above them."""
    out = set()
    if not keywords:
        return out
    for tbl in root.iter(spec["tbl"]):
        rows = [[tc for tc in tr if tc.tag == spec["tc"]] for tr in tbl if tr.tag == spec["tr"]]
        grid = [["\n".join(_text(p, spec) for p in tc.iter(spec["p"])) for tc in row] for row in rows]
        for ri, ci in sensitive_cells(grid, keywords):
            out.update(rows[ri][ci].iter(spec["p"]))
    return out


def redact_paragraph(p, spec, r: Redactor, whole: bool = False) -> int:
    segs = _segments(p, spec)
    text = "".join(t for _, t in segs)
    if whole:
        value = text.strip()
        start = text.find(value)
        changes = [Change(start, start + len(value), KEYWORD_TYPE, KEYWORD_SCORE, r.whole(value))] if value else []
    else:
        changes = r.find(text)
    if not changes:
        return 0
    starts, pos = [], 0
    for _, t in segs:
        starts.append(pos)
        pos += len(t)
    # last change first: an edit only alters text after the changes still to come, so their offsets hold
    for c in sorted(changes, key=lambda c: c.start, reverse=True):
        placed = False
        for (el, original), s0 in zip(segs, starts):
            e0 = s0 + len(original)
            if el is None or e0 <= c.start or s0 >= c.end:
                continue
            cur = el.text or ""
            a, b = max(c.start, s0) - s0, min(c.end, e0) - s0
            el.text = cur[:a] + ("" if placed else c.replacement) + cur[b:]
            el.set(XML_SPACE, "preserve")
            placed = True
    return len(changes)


def _paragraphs(root, spec):
    return list(root.iter(spec["p"]))


def _clear_properties(cp) -> None:
    for name in ("author", "last_modified_by", "title", "subject", "keywords", "comments", "category"):
        try:
            setattr(cp, name, "")
        except Exception:
            pass


def docx(data: bytes, r: Redactor) -> bytes:
    import docx as python_docx
    doc = python_docx.Document(io.BytesIO(data))
    roots = [doc.element.body]
    for section in doc.sections:
        for hf in (section.header, section.first_page_header, section.even_page_header,
                   section.footer, section.first_page_footer, section.even_page_footer):
            if not hf.is_linked_to_previous:
                roots.append(hf._element)
    # footnotes, endnotes and comments live in their own parts
    for rel in doc.part.rels.values():
        if not rel.is_external and rel.reltype.rsplit("/", 1)[-1] in ("footnotes", "endnotes", "comments"):
            part = rel.target_part
            el = getattr(part, "_element", None)
            if el is None:                                # a plain part: edit its XML bytes
                from lxml import etree
                el = etree.fromstring(part.blob)
                for p in _paragraphs(el, WORD):
                    redact_paragraph(p, WORD, r)
                part._blob = etree.tostring(el, xml_declaration=True, encoding="UTF-8", standalone=True)
                continue
            roots.append(el)
    seen = set()
    for root in roots:
        if id(root) in seen:
            continue
        seen.add(id(root))
        whole = _whole_cells(root, WORD, r.keywords)
        for p in _paragraphs(root, WORD):
            redact_paragraph(p, WORD, r, p in whole)
    if r.mode != "unmask":
        _clear_properties(doc.core_properties)
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def pptx(data: bytes, r: Redactor) -> bytes:
    import pptx as python_pptx
    prs = python_pptx.Presentation(io.BytesIO(data))
    for slide in prs.slides:
        whole = _whole_cells(slide._element, SLIDE, r.keywords)
        for p in _paragraphs(slide._element, SLIDE):
            redact_paragraph(p, SLIDE, r, p in whole)
        if slide.has_notes_slide:
            for p in _paragraphs(slide.notes_slide._element, SLIDE):
                redact_paragraph(p, SLIDE, r)
    if r.mode != "unmask":
        _clear_properties(prs.core_properties)
    out = io.BytesIO()
    prs.save(out)
    return out.getvalue()
