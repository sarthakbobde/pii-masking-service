from tests.conftest import ADMIN


def test_settings_read_and_validate(client):
    r = client.get("/v1/admin/settings", headers=ADMIN)
    assert r.json()["settings"]["threshold"] == 40
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"threshold": 200}).status_code == 400
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"nope": 1}).status_code == 400
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"enabled_types": ["NOPE"]}).status_code == 400
    r = client.put("/v1/admin/settings", headers=ADMIN, json={"sensitive_keywords": ["Employee id"]})
    assert r.json()["settings"]["sensitive_keywords"] == ["Employee id"]


def test_settings_apply_to_requests(client):
    h = {}
    client.put("/v1/admin/settings", headers=ADMIN, json={"enabled_types": ["PHONE_NUMBER"], "keywords_enabled": False})
    r = client.post("/v1/mask", headers=h, json={"text": "a@b.com, Salary: 10. Call +91 98765 43210."})
    assert r.json()["text"] == "a@b.com, Salary: 10. Call <PHONE_NUMBER>."


def test_custom_types(client):
    h = {}
    bad = client.post("/v1/admin/custom-types", headers=ADMIN, json={"name": "EMAIL_ADDRESS", "pattern": "x"})
    assert bad.status_code == 400
    assert client.post("/v1/admin/custom-types", headers=ADMIN, json={"name": "X", "pattern": "a*"}).status_code == 400
    r = client.post("/v1/admin/custom-types", headers=ADMIN,
                    json={"name": "employee_id", "pattern": r"\bEMP-\d{5}\b", "confidence": 90})
    assert r.status_code == 201 and r.json()["name"] == "EMPLOYEE_ID"
    tid = r.json()["id"]
    assert "EMPLOYEE_ID" in client.get("/v1/admin/settings", headers=ADMIN).json()["settings"]["enabled_types"]
    assert client.post("/v1/mask", headers=h, json={"text": "Badge EMP-12345 ok"}).json()["text"] == "Badge <EMPLOYEE_ID> ok"
    client.put(f"/v1/admin/custom-types/{tid}", headers=ADMIN, json={"name": "STAFF_ID", "pattern": r"\bEMP-\d{5}\b"})
    assert client.post("/v1/mask", headers=h, json={"text": "Badge EMP-12345 ok"}).json()["text"] == "Badge <STAFF_ID> ok"
    assert client.delete(f"/v1/admin/custom-types/{tid}", headers=ADMIN).status_code == 200
    assert client.post("/v1/mask", headers=h, json={"text": "Badge EMP-12345 ok"}).json()["total"] == 0
    assert client.delete(f"/v1/admin/custom-types/{tid}", headers=ADMIN).status_code == 404
    t = client.post("/v1/admin/custom-types/test", headers=ADMIN, json={"pattern": r"\d+", "text": "a 1 b 22"})
    assert t.json()["matches"] == ["1", "22"]




def test_settings_file_seeds_a_new_database(tmp_path, monkeypatch):
    from pathlib import Path

    from app import policy
    from app.config import config
    from app.db import Database
    monkeypatch.setattr(config, "settings_file", str(Path(__file__).parent.parent / "settings.example.json"))
    db = Database(f"sqlite:///{tmp_path}/seed.db")
    policy.seed(db)
    policy.invalidate()
    s = policy.current(db)
    assert s["allow_list"] == ["hr@example.com"] and "EMPLOYEE_ID" in s["enabled_types"]
    assert [t["name"] for t in policy.custom_types(db)] == ["EMPLOYEE_ID"]
    policy.invalidate()


def test_audit_log_lists_calls_with_counts(client):
    h = {}
    client.post("/v1/mask", headers=h, json={"text": "Mail x.y@corp.com"})
    log = client.get("/v1/admin/audit", headers=ADMIN, params={"operation": "mask", "limit": 5}).json()
    assert log and log[0]["counts"] == {"EMAIL_ADDRESS": 1} and log[0]["caller"] == "testclient" and "key" not in log[0]


def test_admin_needs_the_admin_key(client):
    assert client.get("/v1/admin/settings").status_code == 401
    assert client.get("/v1/admin/settings", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/v1/admin/settings", headers={"X-API-Key": ADMIN["Authorization"][7:]}).status_code == 200
    assert client.get("/v1/admin/settings", headers=ADMIN).status_code == 200
    assert client.get("/v1/admin/audit").status_code == 401 and client.post("/v1/admin/check").status_code == 401


def test_admin_without_a_key_answers_only_from_the_server_itself(client, monkeypatch):
    from app.config import config
    monkeypatch.setattr(config, "admin_key", "")
    r = client.get("/v1/admin/settings")                                 # the test client is not on the server
    assert r.status_code == 403 and "PII_ADMIN_KEY" in r.json()["detail"]
    assert client.get("/v1/admin/overview", headers={"X-Forwarded-For": "10.0.0.5"}).status_code == 403


def test_admin_without_a_key_works_on_loopback_but_not_behind_a_proxy(monkeypatch):
    from fastapi.testclient import TestClient

    from app.config import config
    from app.main import app
    monkeypatch.setattr(config, "admin_key", "")
    with TestClient(app, client=("127.0.0.1", 50000)) as local:
        assert local.get("/v1/admin/overview").status_code == 200
        assert local.get("/v1/admin/overview", headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 403
        assert local.get("/v1/admin/overview", headers={"Forwarded": "for=203.0.113.9"}).status_code == 403
        assert local.get("/admin").status_code == 200


def test_a_short_admin_key_is_refused_at_start(monkeypatch):
    import pytest

    from app import auth
    from app.config import config
    monkeypatch.setattr(config, "admin_key", "too-short")
    with pytest.raises(RuntimeError):
        auth.check_config()
