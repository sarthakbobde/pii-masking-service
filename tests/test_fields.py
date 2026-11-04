"""Fields (the dictionary of known values and labels), and CIN / GSTIN detection."""
import io

from app import policy
from tests.conftest import ADMIN

CIN = "U72200KA2010PTC052901"
GSTIN = "29AABCU9603R1ZM"


def _field(client, name) -> dict:
    return next(f for f in client.get("/v1/admin/fields", headers=ADMIN).json() if f["name"] == name)


def _mask(client, h, text, **options) -> str:
    r = client.post("/v1/mask", headers=h, json={"text": text, **({"options": options} if options else {})})
    assert r.status_code == 200, r.text
    return r.json()["text"]


def test_starter_fields(client):
    names = [f["name"] for f in client.get("/v1/admin/fields", headers=ADMIN).json()]
    assert sorted(names) == sorted(f["name"] for f in policy.STARTER_FIELDS) and len(names) == 12


def test_cin_and_gstin_found_by_format(client, make_key):
    text = f"Registered with CIN {CIN} and GSTIN {GSTIN}."
    assert _mask(client, make_key(["mask"]), text) == "Registered with CIN <IN_CIN> and GSTIN <IN_GSTIN>."


def test_known_values_are_masked_wherever_they_appear(client, make_key):
    h = make_key(["mask"])
    fid = _field(client, "COMPANY_NAME")["id"]
    r = client.post(f"/v1/admin/fields/{fid}/terms", headers=ADMIN, json={"add": ["Acme Technologies Pvt Ltd", "Acme"]})
    assert r.json()["terms"] == ["Acme Technologies Pvt Ltd", "Acme"]
    cin = _field(client, "COMPANY_CIN")["id"]
    client.post(f"/v1/admin/fields/{cin}/terms", headers=ADMIN, json={"add": [CIN]})
    text = f"This agreement is made by ACME Technologies Pvt. Ltd. (CIN {CIN}). Acme will deliver. Acmeville is a town."
    assert _mask(client, h, text) == ("This agreement is made by <COMPANY_NAME>. (CIN <COMPANY_CIN>). <COMPANY_NAME> will "
                                      "deliver. Acmeville is a town.")
    client.post(f"/v1/admin/fields/{fid}/terms", headers=ADMIN, json={"remove": ["acme"]})
    assert _mask(client, h, "Acme will deliver.") == "Acme will deliver."


def test_labels_name_the_value(client, make_key):
    h = make_key(["mask"])
    text = ("Client Name: Globex Pvt. Ltd. The parties agree. Client Authorised Signatory: Mr. Rahul Rao. "
            "Authorised Signatory: Ms. Priya Nair. Registered Office: Plot No. 4, MG Road, Pune.")
    assert _mask(client, h, text) == ("Client Name: <CLIENT_COMPANY_NAME>. The parties agree. Client Authorised Signatory: "
                                      "<CLIENT_SIGNATORY>. Authorised Signatory: <INTERNAL_SIGNATORY>. "
                                      "Registered Office: <COMPANY_ADDRESS>.")


def test_add_change_disable_and_delete_a_field(client, make_key):
    h = make_key(["mask"])
    r = client.post("/v1/admin/fields", headers=ADMIN,
                    json={"name": "project name", "terms": ["Project Falcon"], "labels": ["Project"]})
    assert r.status_code == 201 and r.json()["name"] == "PROJECT_NAME"
    fid = r.json()["id"]
    assert _mask(client, h, "Status of project falcon is green.") == "Status of <PROJECT_NAME> is green."
    assert _mask(client, h, "Project: Orion.") == "Project: <PROJECT_NAME>."
    client.patch(f"/v1/admin/fields/{fid}", headers=ADMIN, json={"enabled": False})
    assert _mask(client, h, "Status of Project Falcon is green.") == "Status of Project Falcon is green."
    client.patch(f"/v1/admin/fields/{fid}", headers=ADMIN, json={"enabled": True, "terms": ["Falcon"]})
    assert _mask(client, h, "Falcon is green.") == "<PROJECT_NAME> is green."
    assert client.delete(f"/v1/admin/fields/{fid}", headers=ADMIN).status_code == 200
    assert _mask(client, h, "Falcon is green.") == "Falcon is green."


def test_field_validation(client):
    post = lambda body: client.post("/v1/admin/fields", headers=ADMIN, json=body).status_code   # noqa: E731
    assert post({"name": "IN_PAN"}) == 400                       # a built-in type
    assert post({"name": "X"}) == 400
    assert post({"name": "SHORT_TERM", "terms": ["a"]}) == 400   # would match everywhere
    assert post({"name": "BAD", "colour": "red"}) == 400
    assert post({"name": "COMPANY_NAME"}) == 409
    client.post("/v1/admin/custom-types", headers=ADMIN, json={"name": "TICKET", "pattern": r"T-\d+"})
    assert post({"name": "TICKET"}) == 409                       # a custom type already has the name


def test_request_fields_add_values_for_one_call(client, make_key):
    h = make_key(["mask"])
    text = "Invoice for Globex Corporation, project Orion."
    out = _mask(client, h, text, fields=[{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Corporation"]},
                                         {"name": "PROJECT", "terms": ["Orion"]}])
    assert out == "Invoice for <CLIENT_COMPANY_NAME>, project <PROJECT>."
    assert _mask(client, h, text) == text                        # nothing stored
    assert client.post("/v1/mask", headers=h, json={"text": text, "options": {"fields": [{"name": "PERSON"}]}}).status_code == 400


def test_field_values_tokenise_and_unmask(client, make_key):
    h = make_key(["tokenise", "unmask"])
    fid = _field(client, "CLIENT_COMPANY_NAME")["id"]
    client.post(f"/v1/admin/fields/{fid}/terms", headers=ADMIN, json={"add": ["Globex Corporation"]})
    t = client.post("/v1/tokenise", headers=h, json={"text": "Signed with Globex Corporation."}).json()
    assert t["text"].startswith("Signed with <CLIENT_COMPANY_NAME_")
    assert client.post("/v1/unmask", headers=h, json={"text": t["text"]}).json()["text"] == "Signed with Globex Corporation."


def test_field_labels_in_word_tables_and_spreadsheets(client, make_key):
    import docx
    import openpyxl
    h = make_key(["mask"])
    d = docx.Document()
    t = d.add_table(rows=2, cols=2)
    t.cell(0, 0).text, t.cell(0, 1).text = "Client Name", "Globex Corporation"
    t.cell(1, 0).text, t.cell(1, 1).text = "Client GSTIN", GSTIN
    buf = io.BytesIO()
    d.save(buf)
    r = client.post("/v1/files/mask", headers=h, files={"file": ("a.docx", buf.getvalue())})
    cells = [c.text for row in docx.Document(io.BytesIO(r.content)).tables[0].rows for c in row.cells]
    assert cells == ["Client Name", "<CLIENT_COMPANY_NAME>", "Client GSTIN", "<CLIENT_GSTIN>"]

    wb = openpyxl.Workbook()
    wb.active.append(["Client Name", "Amount"])
    wb.active.append(["Globex Corporation", 1200])
    buf = io.BytesIO()
    wb.save(buf)
    r = client.post("/v1/files/mask", headers=h, files={"file": ("a.xlsx", buf.getvalue())})
    rows = list(openpyxl.load_workbook(io.BytesIO(r.content)).active.iter_rows(values_only=True))
    assert rows == [("Client Name", "Amount"), ("<CLIENT_COMPANY_NAME>", 1200)]


def test_pan_needs_the_pan_shape(client, make_key):
    text = "PAN AAKCA1234F, having its registered office at Plot 4, Bengaluru 560001."
    assert _mask(client, make_key(["mask"]), text) == "PAN <IN_PAN>, having its registered office at Plot 4, Bengaluru 560001."


def test_a_company_name_ending_in_ltd_takes_its_full_stop(client, make_key):
    h = make_key(["mask"])
    fields = [{"name": "CLIENT_COMPANY_NAME", "terms": ["Globex Retail Pvt Ltd"]}]
    assert _mask(client, h, "Globex Retail Pvt. Ltd., with CIN", fields=fields) == "<CLIENT_COMPANY_NAME>, with CIN"
    assert _mask(client, h, "Signed by Globex Retail Pvt. Ltd. The end.", fields=fields) == "Signed by <CLIENT_COMPANY_NAME>. The end."
