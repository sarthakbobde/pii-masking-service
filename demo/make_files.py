"""Builds the demo input files in demo/files/ (all data is made up)."""
from pathlib import Path

import docx
import openpyxl
import pymupdf
from docx.shared import Pt, RGBColor
from openpyxl.styles import Font, PatternFill

OUT = Path(__file__).parent / "files"


def verhoeff_aadhaar(first11: str) -> str:
    """A made-up Aadhaar number with a valid check digit, so the detector recognises its format."""
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
         [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
         [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    inv = [0,4,3,2,1,5,6,7,8,9]
    c = 0
    for i, ch in enumerate(reversed(first11)):
        c = d[c][p[(i + 1) % 8][int(ch)]]
    n = first11 + str(inv[c])
    return f"{n[:4]} {n[4:8]} {n[8:]}"


AADHAAR = verhoeff_aadhaar("45217896321")


def word():
    d = docx.Document()
    d.sections[0].header.paragraphs[0].text = "CONFIDENTIAL - prepared by priya.nair@acme-hr.com"
    d.add_heading("Offer letter", 0)
    p = d.add_paragraph("Dear Rohan Sharma,")
    p = d.add_paragraph("We are pleased to offer you the role of ")
    p.add_run("Senior Data Engineer").bold = True
    p.add_run(" at Acme Analytics. Please confirm by writing to ")
    r = p.add_run("rohan.sharma@gmail.com")
    r.font.color.rgb = RGBColor(0x1F, 0x4E, 0x9E)
    p.add_run(" or calling us on +91 98450 12345.")
    d.add_paragraph("Your annual CTC: 24,50,000. Joining date is 1 December 2026.")
    d.add_paragraph("Employee id EMP-20417 will be active from your first day.")
    d.add_heading("Details on file", 2)
    t = d.add_table(rows=6, cols=2)
    t.style = "Light Grid Accent 1"
    rows = [("PAN", "BQKPS4821L"), ("Aadhaar No", AADHAAR), ("Date of birth", "14/08/1993"),
            ("Bank account", "50100 2345 6789"), ("Home address", "Flat 302, Lake View Apartments, Pune 411014"),
            ("Corporate card", "4111 1111 1111 1111")]
    for i, (k, v) in enumerate(rows):
        t.cell(i, 0).text, t.cell(i, 1).text = k, v
    d.add_paragraph("")
    d.add_paragraph("For any questions, contact hr@example.com.").runs[0].font.size = Pt(9)
    d.core_properties.author = "Priya Nair"
    d.save(OUT / "offer-letter.docx")


def pdf():
    doc = pymupdf.open()
    page = doc.new_page()
    y = 70
    def line(text, size=11, bold=False, gap=22):
        nonlocal y
        page.insert_text((60, y), text, fontsize=size, fontname="hebo" if bold else "helv")
        y += gap
    line("Customer complaint #CX-88213", 16, True, 34)
    line("Received from Meera Iyer (meera.iyer@outlook.com, +91 99001 23456) on 2 Nov 2026.")
    line("The customer says her card 5555 5555 5555 4444 was charged twice for order 7731.")
    line("Her registered PAN is AKLPI7731Q and Aadhaar " + AADHAAR + ".")
    line("DOB 22/01/1988. Home address: 14 Residency Road, Bengaluru 560025.", gap=34)
    line("Agent notes", 13, True, 26)
    line("Called back on +91 99001 23456. Refund approved; reference RF-55120.")
    line("Escalation contact: support-lead@example.com.")
    page.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(140, 92, 300, 106), "uri": "mailto:meera.iyer@outlook.com"})
    doc.set_metadata({"author": "Meera Iyer", "title": "Complaint CX-88213"})
    doc.save(OUT / "customer-complaint.pdf")


def excel():
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Staff"
    ws.append(["Name", "Email", "Phone", "DOB", "Salary", "Team"])
    for row in [("Ananya Rao", "ananya.rao@acme.com", "+91 90080 11223", "03/05/1991", 1850000, "Data"),
                ("Vikram Singh", "vikram.s@acme.com", "+91 98860 44556", "19/11/1987", 2600000, "Platform"),
                ("Fatima Khan", "fatima.k@acme.com", "+91 97400 77889", "27/02/1995", 1420000, "Support")]:
        ws.append(row)
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F4E9E")
    for col, w in zip("ABCDEF", (16, 24, 18, 12, 12, 12)):
        ws.column_dimensions[col].width = w
    wb.save(OUT / "staff-list.xlsx")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    word(), pdf(), excel()
    print("written to", OUT)
