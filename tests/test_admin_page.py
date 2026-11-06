"""The admin page, the PII protection switch, the overview and the document check."""
import base64
import io

from tests.conftest import ADMIN

EMAIL = "john.doe@acme.com"


def _put(client, **settings):
    r = client.put("/v1/admin/settings", headers=ADMIN, json=settings)
    assert r.status_code == 200, r.text
    return r.json()


def test_admin_page_is_served_with_a_strict_policy(client):
    r = client.get("/admin")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert client.get("/admin/assets/admin.js").status_code == 200
    assert client.get("/admin/assets/admin.css").status_code == 200
    assert client.get("/admin/assets/../main.py").status_code == 404
    assert client.get("/admin/assets/secrets.txt").status_code == 404


def test_the_page_makes_no_unauthenticated_calls_to_admin_data(client):
    assert client.get("/v1/admin/overview").status_code == 401
    assert client.post("/v1/admin/check", files={"file": ("a.txt", b"hi")}).status_code == 401


def test_protection_switch_passes_text_and_files_through(client):
    h = {}
    text = f"Mail {EMAIL}"
    assert client.get("/healthz").json()["protection"] is True
    try:
        _put(client, protection_enabled=False)
        r = client.post("/v1/mask", headers=h, json={"text": text}).json()
        assert r["text"] == text and r["protection"] == "off" and r["total"] == 0
        f = client.post("/v1/files/mask", headers=h, files={"file": ("a.txt", text.encode())})
        assert f.content.decode() == text and f.headers["x-pii-protection"] == "off"
        assert client.get("/healthz").json()["protection"] is False
        assert client.get("/v1/admin/overview", headers=ADMIN).json()["protection_enabled"] is False
    finally:
        _put(client, protection_enabled=True)
    assert client.post("/v1/mask", headers=h, json={"text": text}).json()["text"] == "Mail <EMAIL_ADDRESS>"


def test_protection_switch_must_be_a_boolean(client):
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"protection_enabled": "no"}).status_code == 400


def test_overview(client):
    client.post("/v1/mask", headers={}, json={"text": f"Mail {EMAIL}"})
    o = client.get("/v1/admin/overview", headers=ADMIN).json()
    assert o["protection_enabled"] is True and o["health"]["database"] is True
    assert o["counts"]["fields"] == 12 and o["admin_access"] == "key"
    assert o["last_24h"]["calls"] >= 1 and o["last_24h"]["values"] >= 1 and "EMAIL_ADDRESS" in o["last_24h"]["by_type"]
    assert "limits" in o


def test_scrub_metadata_can_be_switched_off(client):
    import docx
    h = {}
    d = docx.Document()
    d.add_paragraph("Hello")
    d.core_properties.author = "Priya Nair"
    buf = io.BytesIO()
    d.save(buf)
    def author():
        r = client.post("/v1/files/mask", headers=h, files={"file": ("a.docx", buf.getvalue())})
        return docx.Document(io.BytesIO(r.content)).core_properties.author
    assert author() == ""
    try:
        _put(client, scrub_metadata=False)
        assert author() == "Priya Nair"
    finally:
        _put(client, scrub_metadata=True)


def test_check_a_document(client):
    import docx
    d = docx.Document()
    d.add_paragraph(f"Contact {EMAIL} or +91 98765 43210.")
    d.add_paragraph("Salary: 12,40,000.")
    buf = io.BytesIO()
    d.save(buf)
    r = client.post("/v1/admin/check", headers=ADMIN, files={"file": ("offer.docx", buf.getvalue())})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["file_type"] == "docx" and body["total"] == 3
    assert body["counts"] == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1, "SENSITIVE_VALUE": 1}
    assert "Contact <EMAIL_ADDRESS> or <PHONE_NUMBER>." in body["preview"] and EMAIL not in r.text
    masked = base64.b64decode(body["masked_file"])
    assert EMAIL not in "".join(p.text for p in docx.Document(io.BytesIO(masked)).paragraphs)


def test_check_with_extra_options_and_errors(client):
    r = client.post("/v1/admin/check", headers=ADMIN, files={"file": ("a.txt", b"Project Falcon is late")},
                    data={"options": '{"fields": [{"name": "PROJECT", "terms": ["Project Falcon"]}]}'})
    assert r.json()["preview"] == "<PROJECT> is late"
    assert client.post("/v1/admin/check", headers=ADMIN, files={"file": ("a.exe", b"MZ")}).status_code == 415
    assert client.post("/v1/admin/check", headers=ADMIN, files={"file": ("a.txt", b"")}).status_code == 400
    assert client.post("/v1/admin/check", headers=ADMIN, files={"file": ("a.txt", b"x")}, data={"options": "[1]"}).status_code == 400
