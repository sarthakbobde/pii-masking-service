import json

from sqlalchemy import select

from app import detect
from app.db import AuditEntry, VaultEntry, get_db

EMAIL = "john.doe@acme.com"
TEXT = f"Mail {EMAIL} or call +91 98765 43210. Salary: 12,40,000. PAN ABCDE1234F."


def test_health_needs_no_key(client):
    r = client.get("/healthz")
    assert r.json()["database"] is True and r.json()["vault"] is True


def test_key_required(client):
    assert client.post("/v1/mask", json={"text": TEXT}).status_code == 401
    assert client.post("/v1/mask", json={"text": TEXT}, headers={"X-API-Key": "nope"}).status_code == 401


def test_mask_labels_and_findings_without_values(client, make_key):
    r = client.post("/v1/mask", json={"text": TEXT}, headers=make_key(["mask"]))
    assert r.status_code == 200
    body = r.json()
    assert body["text"] == "Mail <EMAIL_ADDRESS> or call <PHONE_NUMBER>. Salary: <SENSITIVE_VALUE>. PAN <IN_PAN>."
    assert body["counts"] == {"EMAIL_ADDRESS": 1, "IN_PAN": 1, "PHONE_NUMBER": 1, "SENSITIVE_VALUE": 1}
    f = body["findings"][0]
    assert (f["type"], TEXT[f["start"]:f["end"]]) == ("EMAIL_ADDRESS", EMAIL)
    assert EMAIL not in json.dumps(body["findings"]) and "12,40,000" not in r.text


def test_already_masked_text_is_left_alone(client, make_key):
    text = "Contact <EMAIL_ADDRESS> or <EMAIL_ADDRESS_1a2b3c4d>."
    assert client.post("/v1/mask", json={"text": text}, headers=make_key(["mask"])).json()["text"] == text


def test_overrides(client, make_key):
    h = make_key(["mask"])
    r = client.post("/v1/mask", headers=h, json={"text": TEXT, "options": {"types": ["EMAIL_ADDRESS"], "keywords": [],
                                                                           "allow_list": [EMAIL]}})
    assert r.json()["total"] == 0
    r = client.post("/v1/mask", headers=h, json={"text": "Employee id: E-1234", "options": {"keywords": ["employee id"]}})
    assert r.json()["text"] == "Employee id: <SENSITIVE_VALUE>"
    assert client.post("/v1/mask", headers=h, json={"text": "x", "options": {"types": ["NOPE"]}}).status_code == 400
    assert client.post("/v1/mask", headers=h, json={"text": "x", "options": {"threshold": 5}}).status_code == 400


def test_overrides_can_be_switched_off(client, make_key):
    from tests.conftest import ADMIN
    client.put("/v1/admin/settings", headers=ADMIN, json={"allow_overrides": False})
    r = client.post("/v1/mask", headers=make_key(["mask"]), json={"text": TEXT, "options": {"types": ["EMAIL_ADDRESS"]}})
    assert r.status_code == 403


def test_tokenise_is_deterministic_per_scope_and_reversible(client, make_key):
    h = make_key(["tokenise", "unmask"], ["team-a", "team-b"])
    a1 = client.post("/v1/tokenise", headers=h, json={"text": TEXT}).json()
    a2 = client.post("/v1/tokenise", headers=h, json={"text": f"Again {EMAIL.upper()}"}).json()
    b = client.post("/v1/tokenise", headers=h, json={"text": TEXT, "scope": "team-b"}).json()
    assert a1["scope"] == "team-a" and EMAIL not in a1["text"]
    token = a1["findings"][0]["replacement"]
    assert token.startswith("<EMAIL_ADDRESS_") and token in a2["text"]
    assert token not in b["text"]
    back = client.post("/v1/unmask", headers=h, json={"text": a1["text"]}).json()
    assert back["text"] == TEXT and back["total"] == 4 and back["unknown_tokens"] == 0
    other = client.post("/v1/unmask", headers=h, json={"text": a1["text"], "scope": "team-b"}).json()
    assert other["text"] == a1["text"] and other["unknown_tokens"] == 4


def test_vault_holds_no_plain_values(client, make_key):
    client.post("/v1/tokenise", headers=make_key(["tokenise"]), json={"text": TEXT})
    with get_db().session() as s:
        rows = s.scalars(select(VaultEntry)).all()
    assert rows and all(EMAIL not in (r.value_encrypted + r.value_hash + r.token) for r in rows)


def test_permissions_and_scopes(client, make_key):
    h = make_key(["mask"], ["team-a"])
    assert client.post("/v1/tokenise", headers=h, json={"text": TEXT}).status_code == 403
    assert client.post("/v1/unmask", headers=h, json={"text": TEXT}).status_code == 403
    assert client.get("/v1/admin/keys", headers=h).status_code == 403
    t = make_key(["tokenise"], ["team-a"])
    assert client.post("/v1/tokenise", headers=t, json={"text": TEXT, "scope": "team-b"}).status_code == 403
    anyscope = make_key(["tokenise"], ["*"])
    assert client.post("/v1/tokenise", headers=anyscope, json={"text": TEXT}).status_code == 403   # no default scope
    assert client.post("/v1/tokenise", headers=anyscope, json={"text": TEXT, "scope": "x"}).status_code == 200


def test_rate_limit(client, make_key):
    h = make_key(["mask"], rate_limit=2)
    codes = [client.post("/v1/mask", headers=h, json={"text": "hello"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_every_call_is_audited_without_values(client, make_key):
    h = make_key(["mask"])
    client.post("/v1/mask", headers=h, json={"text": TEXT})
    with get_db().session() as s:
        e = s.scalars(select(AuditEntry).where(AuditEntry.operation == "mask").order_by(AuditEntry.id.desc())).first()
        dump = json.dumps([[a.counts, a.detail, a.scope] for a in s.scalars(select(AuditEntry))])
    assert e.status == 200 and e.total == 4 and e.counts["EMAIL_ADDRESS"] == 1 and e.key_name.startswith("svc-")
    assert EMAIL not in dump and "12,40,000" not in dump


def test_fails_closed(client, make_key, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("detector down")
    monkeypatch.setattr(detect, "detect", boom)
    r = client.post("/v1/mask", headers=make_key(["mask"]), json={"text": TEXT})
    assert r.status_code == 500 and EMAIL not in r.text


def test_text_length_limit(client, make_key, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "max_text_chars", 10)
    assert client.post("/v1/mask", headers=make_key(["mask"]), json={"text": "x" * 11}).status_code == 413
