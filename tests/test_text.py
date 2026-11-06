import json

from sqlalchemy import select

from app import detect
from app.db import AuditEntry, get_db
from tests.conftest import ADMIN

EMAIL = "john.doe@acme.com"
TEXT = f"Mail {EMAIL} or call +91 98765 43210. Salary: 12,40,000. PAN ABCDE1234F."


def test_health_needs_no_key(client):
    r = client.get("/healthz")
    assert r.json()["database"] is True and "vault" not in r.json()



def test_mask_labels_and_findings_without_values(client):
    r = client.post("/v1/mask", json={"text": TEXT}, headers={})
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "Mail <EMAIL_ADDRESS> or call <PHONE_NUMBER>. Salary: <SENSITIVE_VALUE>. PAN <IN_PAN>."
    assert body["counts"] == {"EMAIL_ADDRESS": 1, "IN_PAN": 1, "PHONE_NUMBER": 1, "SENSITIVE_VALUE": 1}
    f = body["findings"][0]
    assert (f["type"], TEXT[f["start"]:f["end"]]) == ("EMAIL_ADDRESS", EMAIL)
    assert EMAIL not in json.dumps(body["findings"]) and "12,40,000" not in r.text


def test_already_masked_text_is_left_alone(client):
    text = "Contact <EMAIL_ADDRESS> or <EMAIL_ADDRESS_1a2b3c4d>."
    assert client.post("/v1/mask", json={"text": text}, headers={}).json()["text"] == text


def test_overrides(client):
    h = {}
    r = client.post("/v1/mask", headers=h, json={"text": TEXT, "options": {"types": ["EMAIL_ADDRESS"], "keywords": [],
                                                                           "allow_list": [EMAIL]}})
    assert r.json()["total"] == 0
    r = client.post("/v1/mask", headers=h, json={"text": "Employee id: E-1234", "options": {"keywords": ["employee id"]}})
    assert r.json()["text"] == "Employee id: <SENSITIVE_VALUE>"
    assert client.post("/v1/mask", headers=h, json={"text": "x", "options": {"types": ["NOPE"]}}).status_code == 400
    assert client.post("/v1/mask", headers=h, json={"text": "x", "options": {"threshold": 5}}).status_code == 400


def test_overrides_can_be_switched_off(client):
    from tests.conftest import ADMIN
    client.put("/v1/admin/settings", headers=ADMIN, json={"allow_overrides": False})
    r = client.post("/v1/mask", headers={}, json={"text": TEXT, "options": {"types": ["EMAIL_ADDRESS"]}})
    assert r.status_code == 403






def test_every_call_is_audited_without_values(client):
    h = {}
    client.post("/v1/mask", headers=h, json={"text": TEXT})
    with get_db().session() as s:
        e = s.scalars(select(AuditEntry).where(AuditEntry.operation == "mask").order_by(AuditEntry.id.desc())).first()
        dump = json.dumps([[a.counts, a.detail, a.scope] for a in s.scalars(select(AuditEntry))])
    assert e.status == 200 and e.total == 4 and e.counts["EMAIL_ADDRESS"] == 1 and e.key_name == "testclient"
    assert EMAIL not in dump and "12,40,000" not in dump


def test_fails_closed(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("detector down")
    monkeypatch.setattr(detect, "detect", boom)
    r = client.post("/v1/mask", headers={}, json={"text": TEXT})
    assert r.status_code == 500 and EMAIL not in r.text


def test_text_length_limit(client, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "max_text_chars", 10)
    assert client.post("/v1/mask", headers={}, json={"text": "x" * 11}).status_code == 413



def test_masking_needs_no_key(client):
    r = client.post("/v1/mask", json={"text": TEXT})
    assert r.status_code == 200 and "<EMAIL_ADDRESS>" in r.json()["text"]
    f = client.post("/v1/files/mask", files={"file": ("a.txt", TEXT.encode())})
    assert f.status_code == 200 and "<EMAIL_ADDRESS>" in f.content.decode()


def test_only_masking_is_offered(client):
    """There is no way to put a hidden value back: those endpoints do not exist."""
    for path in ("/v1/tokenise", "/v1/unmask", "/v1/files/tokenise", "/v1/files/unmask", "/v1/admin/vault", "/v1/admin/keys"):
        assert client.post(path, headers=ADMIN, json={"text": TEXT}).status_code in (404, 405), path
