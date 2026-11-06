"""The CMS API (specification A.8): POST /api/v1/documents/mask, then status and download."""
import io

from app import jobs
from tests.conftest import ADMIN

EMAIL = "john.doe@acme.com"
LINE = f"Contact {EMAIL} or +91 98765 43210. Salary: 12,40,000."
URL = "/api/v1/documents/mask"


def make_docx() -> bytes:
    import docx
    d = docx.Document()
    d.add_paragraph(LINE)
    d.core_properties.author = "John Doe"
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def make_pdf(text=LINE) -> bytes:
    import pymupdf
    doc = pymupdf.open()
    if text:
        doc.new_page().insert_text((72, 90), text, fontsize=11)
    else:
        doc.new_page()
    return doc.tobytes()


def submit(client, headers, name="ACME_MSA_2026.docx", data=None, **form):
    form = {"contract_id": "CMS-CONTRACT-12345", "version": "2.0", **form}
    form = {k: v for k, v in form.items() if v is not None}
    return client.post(URL, headers=headers, files={"file": (name, data if data is not None else make_docx())}, data=form)


def error(r, status, code):
    assert r.status_code == status, r.text
    body = r.json()
    assert set(body) == {"error"} and body["error"]["code"] == code and set(body["error"]) == {"code", "message", "details"}, body
    return body["error"]["message"]


def test_mask_a_docx_end_to_end(client, make_key):
    import docx
    h = make_key(["mask"])
    r = submit(client, h, output_filename="ACME_MSA_20.docx")
    assert r.status_code == 200, r.text
    job = r.json()
    assert job["status"] == "completed" and job["contract_id"] == "CMS-CONTRACT-12345" and job["version"] == "2.0"
    assert job["job_id"].startswith("mask-") and job["output_filename"] == "ACME_MSA_20.docx"
    assert job["masked_fields_count"] == 3 and job["field_types"] == {"EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1, "SENSITIVE_VALUE": 1}
    assert EMAIL not in r.text and job["error_code"] is None

    st = client.get(f"{URL}/{job['job_id']}/status", headers=h)
    assert st.status_code == 200 and st.json() == job

    dl = client.get(f"{URL}/{job['job_id']}/download", headers=h)
    assert dl.status_code == 200
    assert dl.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument.wordprocessingml")
    assert dl.headers["content-disposition"] == 'attachment; filename="ACME_MSA_20.docx"'
    assert dl.headers["x-contract-id"] == "CMS-CONTRACT-12345" and dl.headers["x-version"] == "2.0"
    assert dl.headers["x-original-filename"] == "ACME_MSA_2026.docx" and dl.headers["x-masked-fields-count"] == "3"
    d = docx.Document(io.BytesIO(dl.content))
    assert d.paragraphs[0].text == "Contact <EMAIL_ADDRESS> or <PHONE_NUMBER>. Salary: <SENSITIVE_VALUE>."
    assert d.core_properties.author == ""
    assert EMAIL.encode() not in dl.content


def test_mask_a_pdf_in_the_same_format(client, make_key):
    import pymupdf
    h = make_key(["mask"])
    job = submit(client, h, name="contract.pdf", data=make_pdf()).json()
    assert job["output_filename"] == "contract_Masked.pdf" and job["pages"] == 1          # the default name
    dl = client.get(f"{URL}/{job['job_id']}/download", headers=h)
    assert dl.headers["content-type"] == "application/pdf"
    text = pymupdf.open(stream=dl.content, filetype="pdf")[0].get_text()
    assert "<EMAIL_ADDRESS>" in text and EMAIL not in text and EMAIL.encode() not in dl.content


def test_output_filename_is_made_safe(client, make_key):
    h = make_key(["mask"])
    out = submit(client, h, output_filename="..\\..\\evil\"name\r\n.txt").json()["output_filename"]
    assert out.endswith(".docx") and "/" not in out and "\\" not in out and '"' not in out and "\n" not in out
    assert submit(client, h, output_filename="Report").json()["output_filename"] == "Report.docx"


def test_validation_errors(client, make_key):
    h = make_key(["mask"])
    assert error(submit(client, h, version=None), 400, "VALIDATION_ERROR") == "version is required"
    assert error(submit(client, h, contract_id=None), 400, "VALIDATION_ERROR") == "contract_id is required"
    error(submit(client, h, version="2.0\r\nX-Evil: 1"), 400, "VALIDATION_ERROR")
    error(client.post(URL, headers=h, data={"contract_id": "C-1", "version": "1"}), 400, "VALIDATION_ERROR")   # no file


def test_empty_and_unsupported_files(client, make_key):
    h = make_key(["mask"])
    assert error(submit(client, h, data=b""), 400, "EMPTY_FILE") == "Uploaded file is empty"
    msg = error(submit(client, h, name="prices.xlsx", data=b"x"), 400, "UNSUPPORTED_MEDIA_TYPE")
    assert msg == "File type .xlsx is not supported. Accepted: .docx, .pdf"
    error(submit(client, h, name="archive", data=b"x"), 400, "UNSUPPORTED_MEDIA_TYPE")


def test_too_large(client, make_key, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "max_upload_mb", 0)
    assert error(submit(client, make_key(["mask"])), 413, "PAYLOAD_TOO_LARGE") == "File exceeds maximum allowed size of 0 MB"


def test_unreadable_documents(client, make_key):
    import pymupdf
    h = make_key(["mask"])
    msg = "Document could not be read."
    assert error(submit(client, h, data=b"PK\x03\x04 not really a docx"), 422, "UNREADABLE_DOCUMENT").startswith(msg)
    error(submit(client, h, name="a.pdf", data=b"%PDF-1.4 garbage"), 422, "UNREADABLE_DOCUMENT")
    locked = pymupdf.open()
    locked.new_page().insert_text((72, 90), LINE)
    secret = locked.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    error(submit(client, h, name="locked.pdf", data=secret), 422, "UNREADABLE_DOCUMENT")
    error(submit(client, h, name="blank.pdf", data=make_pdf("")), 422, "UNREADABLE_DOCUMENT")      # nothing to read


def test_masking_failure_returns_no_file(client, make_key, monkeypatch):
    from app import files
    def boom(*a, **k):
        raise RuntimeError("detector down")
    monkeypatch.setattr(files, "process", boom)
    msg = error(submit(client, make_key(["mask"])), 500, "MASKING_FAILED")
    assert "Contact support" in msg and EMAIL not in msg


def test_a_job_belongs_to_the_key_that_made_it(client, make_key):
    a, b = make_key(["mask"]), make_key(["mask"])
    job_id = submit(client, a).json()["job_id"]
    assert client.get(f"{URL}/{job_id}/status", headers=a).status_code == 200
    assert error(client.get(f"{URL}/{job_id}/status", headers=b), 404, "JOB_NOT_FOUND") == f"No job found with id {job_id}"
    error(client.get(f"{URL}/{job_id}/download", headers=b), 404, "JOB_NOT_FOUND")
    error(client.get(f"{URL}/mask-doesnotexist/status", headers=a), 404, "JOB_NOT_FOUND")


def test_jobs_expire_and_the_store_is_bounded(client, make_key, monkeypatch):
    from app.config import config
    h = make_key(["mask"])
    job_id = submit(client, h).json()["job_id"]
    monkeypatch.setattr(config, "job_ttl_minutes", 60)
    jobs.store._jobs[job_id].expires = 0          # as if the time was up
    error(client.get(f"{URL}/{job_id}/status", headers=h), 404, "JOB_NOT_FOUND")
    monkeypatch.setattr(config, "job_max_mb", 0)          # room for only the newest job
    first = submit(client, h).json()["job_id"]
    second = submit(client, h).json()["job_id"]
    assert client.get(f"{URL}/{first}/status", headers=h).status_code == 404
    assert client.get(f"{URL}/{second}/status", headers=h).status_code == 200


def test_errors_for_keys_use_the_same_format(client, make_key):
    error(client.post(URL, files={"file": ("a.docx", make_docx())}, data={"contract_id": "C", "version": "1"}), 401, "UNAUTHORIZED")
    admin_only = client.post("/v1/admin/keys", headers=ADMIN, json={"name": "just-admin", "permissions": ["admin"]}).json()["key"]
    error(submit(client, {"X-API-Key": admin_only}), 403, "FORBIDDEN")
    limited = make_key(["mask"], rate_limit=1)
    submit(client, limited)
    r = submit(client, limited)
    error(r, 429, "RATE_LIMITED")
    assert "retry-after" in r.headers


def test_protection_off_returns_the_file_unchanged_and_says_so(client, make_key):
    h = make_key(["mask"])
    data = make_docx()
    try:
        client.put("/v1/admin/settings", headers=ADMIN, json={"protection_enabled": False})
        job = submit(client, h, data=data).json()
        assert job["protection"] == "off" and job["masked_fields_count"] == 0
        dl = client.get(f"{URL}/{job['job_id']}/download", headers=h)
        assert dl.content == data and dl.headers["x-pii-protection"] == "off"
    finally:
        client.put("/v1/admin/settings", headers=ADMIN, json={"protection_enabled": True})


def test_the_audit_log_has_counts_and_the_contract_but_no_values(client, make_key):
    h = make_key(["mask"])
    submit(client, h)
    entry = client.get("/v1/admin/audit", headers=ADMIN, params={"operation": "cms_mask", "limit": 1}).json()[0]
    assert entry["status"] == 200 and entry["total"] == 3 and "CMS-CONTRACT-12345" in entry["detail"]
    assert EMAIL not in str(entry) and "12,40,000" not in str(entry)
