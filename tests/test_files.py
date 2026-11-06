import io
import json

import pytest

from app.files.pdf import tessdata

EMAIL = "john.doe@acme.com"
PHONE = "+91 98765 43210"
LINE = f"Contact {EMAIL} or {PHONE} today."


def _post(client, h, mode, name, data, **form):
    return client.post(f"/v1/files/{mode}", headers=h, files={"file": (name, data)}, data=form)


def _summary(r) -> dict:
    return json.loads(r.headers["X-PII-Summary"])


# ---- sample files -------------------------------------------------------------------------------------------------------------
def make_docx() -> bytes:
    import docx
    d = docx.Document()
    p = d.add_paragraph("Contact ")
    p.add_run("john.doe").bold = True                      # the value is split over two runs with different formatting
    p.add_run(f"@acme.com or {PHONE} today.")
    d.add_paragraph("Salary: 12,40,000.")
    t = d.add_table(rows=2, cols=2)
    t.cell(0, 0).text, t.cell(0, 1).text = "Email", "jane@corp.org"
    t.cell(1, 0).text, t.cell(1, 1).text = "Home address", "12 MG Road, Pune"      # keyword in one cell, value in the next
    d.sections[0].header.paragraphs[0].text = "Owner mary@corp.org"
    d.core_properties.author = "John Doe"
    out = io.BytesIO()
    d.save(out)
    return out.getvalue()


def docx_text(data: bytes) -> str:
    import docx
    d = docx.Document(io.BytesIO(data))
    parts = [p.text for p in d.paragraphs] + [c.text for row in d.tables[0].rows for c in row.cells]
    parts += [p.text for p in d.sections[0].header.paragraphs]
    return "\n".join(parts)


def make_pptx() -> bytes:
    import pptx
    from pptx.util import Inches
    prs = pptx.Presentation()
    s = prs.slides.add_slide(prs.slide_layouts[5])
    s.shapes.title.text = "Team contacts"
    s.shapes.add_textbox(Inches(1), Inches(2), Inches(6), Inches(1)).text_frame.text = LINE
    s.notes_slide.notes_text_frame.text = "Speaker: call jane@corp.org"
    out = io.BytesIO()
    prs.save(out)
    return out.getvalue()


def pptx_text(data: bytes) -> str:
    import pptx
    prs = pptx.Presentation(io.BytesIO(data))
    out = []
    for s in prs.slides:
        out += [sh.text_frame.text for sh in s.shapes if sh.has_text_frame]
        out.append(s.notes_slide.notes_text_frame.text)
    return "\n".join(out)


def make_xlsx() -> bytes:
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Name", "Email", "DOB", "Score"])
    ws.append(["Asha", EMAIL, "1990-03-12", 42])
    ws.append(["Ravi", "ravi@corp.org", "1988-07-01", 7])
    ws.append([])
    ws.append(["Salary:", 1240000])
    ws.append(["Total", "=SUM(D2:D3)"])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def make_pdf(text_lines) -> bytes:
    import pymupdf
    doc = pymupdf.open()
    page = doc.new_page()
    y = 72
    for line in text_lines:
        page.insert_text((72, y), line, fontsize=11)
        y += 20
    page.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(72, 60, 300, 76), "uri": f"mailto:{EMAIL}"})
    doc.set_metadata({"author": "John Doe"})
    return doc.tobytes()


def make_scanned_pdf() -> bytes:
    """A page that is only an image of text (as a scanner makes it)."""
    import pymupdf
    src = pymupdf.open()
    p = src.new_page()
    p.insert_text((72, 100), f"Email {EMAIL} please", fontsize=16)
    pix = p.get_pixmap(dpi=200)
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_image(page.rect, pixmap=pix)
    return doc.tobytes()


# ---- tests ----------------------------------------------------------------------------------------------------------------
def test_text_and_markdown(client):
    h = {}
    r = _post(client, h, "mask", "notes.md", f"# Notes\n\n{LINE}\n".encode())
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
    assert r.content.decode() == "# Notes\n\nContact <EMAIL_ADDRESS> or <PHONE_NUMBER> today.\n"
    assert 'filename="notes.masked.md"' in r.headers["content-disposition"]
    assert _summary(r)["counts"] == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1}


def test_csv_keyword_column(client):
    data = b"name,email,salary\nAsha,asha@corp.org,1200000\n"
    r = _post(client, {}, "mask", "people.csv", data)
    assert r.content.decode().splitlines() == ["name,email,salary", "Asha,<EMAIL_ADDRESS>,<SENSITIVE_VALUE>"]


def test_docx_mask_keeps_formatting_and_clears_author(client):
    r = _post(client, {}, "mask", "letter.docx", make_docx())
    assert r.status_code == 200
    text = docx_text(r.content)
    assert EMAIL not in text and "john.doe" not in text and "jane@corp.org" not in text and "mary@corp.org" not in text
    assert "Contact <EMAIL_ADDRESS> or <PHONE_NUMBER> today." in text and "Salary: <SENSITIVE_VALUE>." in text
    assert "MG Road" not in text and "Home address\n<SENSITIVE_VALUE>" in text
    import docx
    d = docx.Document(io.BytesIO(r.content))
    assert d.paragraphs[0].runs[1].bold and d.core_properties.author == ""



def test_pptx(client):
    r = _post(client, {}, "mask", "deck.pptx", make_pptx())
    text = pptx_text(r.content)
    assert "Contact <EMAIL_ADDRESS> or <PHONE_NUMBER> today." in text and "jane@corp.org" not in text
    assert "Team contacts" in text


def test_xlsx(client):
    import openpyxl
    r = _post(client, {}, "mask", "staff.xlsx", make_xlsx())
    ws = openpyxl.load_workbook(io.BytesIO(r.content)).active
    rows = [[c.value for c in row] for row in ws.iter_rows()]
    assert rows[0] == ["Name", "Email", "DOB", "Score"]                             # headers stay readable
    assert rows[1][:4] == ["Asha", "<EMAIL_ADDRESS>", "<SENSITIVE_VALUE>", 42]      # DOB is a keyword column
    assert rows[2][2] == "<SENSITIVE_VALUE>"
    assert rows[4][:2] == ["Salary:", "<SENSITIVE_VALUE>"]                          # keyword label beside its value
    assert rows[5][1] == "=SUM(D2:D3)"                                              # formulas untouched


def test_pdf_true_redaction(client):
    import pymupdf
    src = make_pdf([LINE, "Salary: 12,40,000.", "Nothing to see here."])
    r = _post(client, {}, "mask", "report.pdf", src)
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    doc = pymupdf.open(stream=r.content, filetype="pdf")
    text = doc[0].get_text()
    assert EMAIL not in text and "98765" not in text and "12,40,000" not in text
    assert "<EMAIL_ADDRESS>" in text and "Nothing to see here." in text
    assert EMAIL.encode() not in r.content                       # not hidden under a box: gone from the file
    assert not doc[0].get_links() and not doc.metadata.get("author")
    s = _summary(r)
    assert s["pages"] == 1 and s["counts"]["EMAIL_ADDRESS"] == 1



def test_scanned_pdf_without_ocr_is_reported(client):
    from tests.conftest import ADMIN
    client.put("/v1/admin/settings", headers=ADMIN, json={"ocr_enabled": False})
    r = _post(client, {}, "mask", "scan.pdf", make_scanned_pdf())
    assert r.status_code == 200 and _summary(r)["unprocessed_image_pages"] == [1]


@pytest.mark.skipif(tessdata() is None, reason="Tesseract language data not installed (set PII_TESSDATA_DIR)")
def test_scanned_pdf_with_ocr(client):
    import pymupdf
    r = _post(client, {}, "mask", "scan.pdf", make_scanned_pdf())
    s = _summary(r)
    assert s["ocr_pages"] == [1] and s["counts"].get("EMAIL_ADDRESS") == 1
    page = pymupdf.open(stream=r.content, filetype="pdf")[0]
    ocr = page.get_textpage_ocr(full=True, dpi=300, tessdata=tessdata())
    assert "acme" not in page.get_text(textpage=ocr)


def test_file_checks(client):
    h = {}
    assert _post(client, h, "mask", "virus.exe", b"MZ").status_code == 415
    assert _post(client, h, "mask", "fake.pdf", b"hello").status_code == 415
    assert _post(client, h, "mask", "fake.docx", b"PK\x03\x04nope").status_code == 415
    assert _post(client, h, "mask", "empty.txt", b"").status_code == 400
    assert _post(client, h, "mask", "x.txt", b"hi", options="[1]").status_code == 400


def test_upload_limit(client, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "max_upload_mb", 0)
    assert _post(client, {}, "mask", "x.txt", b"hello").status_code == 413


def test_table_keywords_headers_and_key_value_rows():
    from app.files.sheet import sensitive_cells
    groups = [("SENSITIVE_VALUE", ["Salary", "DOB", "PAN", "Aadhaar No"]), ("CLIENT_COMPANY_NAME", ["Client Name"])]
    staff = [["Name", "DOB", "Salary", "Team"], ["Asha", "03/05/1991", 1850000, "Data"]]
    assert sensitive_cells(staff, groups) == {(1, 1): "SENSITIVE_VALUE", (1, 2): "SENSITIVE_VALUE"}   # "Team" stays
    key_value = [["PAN", "BQKPS4821L"], ["Aadhaar No", "4521 7896 3214"], ["Client Name:", "Globex"], ["Team", "Data"]]
    assert sensitive_cells(key_value, groups) == {(0, 1): "SENSITIVE_VALUE", (1, 1): "SENSITIVE_VALUE",
                                                  (2, 1): "CLIENT_COMPANY_NAME"}       # labels in the first column stay
