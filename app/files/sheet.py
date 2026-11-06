"""Spreadsheets (.xlsx) and CSV: replace personal data cell by cell.

Besides what detection finds inside each cell, tables carry keywords in their structure:
* a header cell that is a sensitive keyword ("Salary", "DOB") makes every value below it in that column sensitive;
* a cell that is just a keyword ("Salary:") makes the next non-empty cell to its right sensitive.
Such cells are replaced whole by `<SENSITIVE_VALUE>` (or its token), numbers and dates included.
Formulas are left alone. A number is checked as text (a phone number stored as a number is still found); a number that
is replaced becomes text. Comments are checked too. Workbook properties (creator, last modified by) are cleared.
Not covered: charts' own text, shapes and text boxes (openpyxl does not keep shapes: they are dropped on save).
"""
import csv
import io
from datetime import date, datetime, time

from app.detect import label_of
from app.redact import Redactor

LOOK_RIGHT = 3          # how far a keyword label looks for its value


def sensitive_cells(grid: list[list], groups) -> dict[tuple[int, int], str]:
    """{(row, col): what the cell becomes} for cells that are sensitive because of a keyword or field label: as the
    header of their column, or as the cell to their left. `groups` is [(what the value becomes, labels)]."""
    if not groups:
        return {}
    out: dict[tuple[int, int], str] = {}

    def label(v) -> str | None:
        return label_of(v, groups) if isinstance(v, str) else None

    header = next((i for i, row in enumerate(grid) if any(v not in (None, "") for v in row)), None)
    header_cols: dict[int, str] = {}
    if header is not None:
        for c, v in enumerate(grid[header]):
            below = [grid[r][c] for r in range(header + 1, len(grid)) if c < len(grid[r])]
            entity = label(v)
            # a column header only when the cells below are values, not more labels (a key-value table)
            if entity and not any(label(x) for x in below):
                header_cols[c] = entity
        for r in range(header + 1, len(grid)):
            for c, entity in header_cols.items():
                if c < len(grid[r]) and grid[r][c] not in (None, ""):
                    out[(r, c)] = entity
    for r, row in enumerate(grid):
        for c, v in enumerate(row):
            if r == header and c in header_cols:
                continue                                  # a column header is not a label for the cell beside it
            entity = label(v)
            if entity:
                for c2 in range(c + 1, min(len(row), c + 1 + LOOK_RIGHT)):
                    nxt = row[c2]
                    if nxt in (None, ""):
                        continue
                    if not (isinstance(nxt, str) and (label(nxt) or nxt.startswith("="))):
                        out[(r, c2)] = entity
                    break
    return out


def _as_text(v) -> str:
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (datetime, date, time)):
        return v.isoformat()
    return str(v)


def xlsx(data: bytes, r: Redactor) -> bytes:
    import openpyxl
    from openpyxl.comments import Comment
    wb = openpyxl.load_workbook(io.BytesIO(data))
    for ws in wb.worksheets:
        rows = list(ws.iter_rows())
        grid = [[c.value for c in row] for row in rows]
        whole = sensitive_cells(grid, r.label_groups)
        for ri, row in enumerate(rows):
            for ci, cell in enumerate(row):
                v = cell.value
                if v is None or cell.data_type == "f" or (isinstance(v, str) and v.startswith("=")):
                    pass
                elif (ri, ci) in whole:
                    cell.value = r.whole(_as_text(v), whole[(ri, ci)])
                elif isinstance(v, str):
                    new, changes = r.run(v)
                    if changes:
                        cell.value = new
                elif isinstance(v, (int, float)) and not isinstance(v, bool):
                    new, changes = r.run(_as_text(v))
                    if changes:
                        cell.value = new
                if cell.comment is not None and cell.comment.text:
                    new, changes = r.run(cell.comment.text)
                    if changes:
                        cell.comment = Comment(new, "")
    if r.scrub:
        wb.properties.creator = ""
        wb.properties.lastModifiedBy = ""
        wb.properties.title = wb.properties.subject = wb.properties.keywords = wb.properties.description = None
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def csv_bytes(data: bytes, r: Redactor, decode, encode) -> bytes:
    text, enc = decode(data)
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    grid = [list(row) for row in csv.reader(io.StringIO(text, newline=""), dialect)]
    whole = sensitive_cells(grid, r.label_groups)
    for ri, row in enumerate(grid):
        for ci, v in enumerate(row):
            if (ri, ci) in whole:
                row[ci] = r.whole(v, whole[(ri, ci)])
            elif v:
                row[ci] = r.run(v)[0]
    out = io.StringIO(newline="")
    w = csv.writer(out, delimiter=dialect.delimiter, quotechar=dialect.quotechar or '"',
                   lineterminator="\r\n" if "\r\n" in text[:4096] else "\n", quoting=csv.QUOTE_MINIMAL)
    w.writerows(grid)
    return encode(out.getvalue(), enc)
