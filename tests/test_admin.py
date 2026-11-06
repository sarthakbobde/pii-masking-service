from tests.conftest import ADMIN


def test_settings_read_and_validate(client):
    r = client.get("/v1/admin/settings", headers=ADMIN)
    assert r.json()["settings"]["threshold"] == 40
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"threshold": 200}).status_code == 400
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"nope": 1}).status_code == 400
    assert client.put("/v1/admin/settings", headers=ADMIN, json={"enabled_types": ["NOPE"]}).status_code == 400
    r = client.put("/v1/admin/settings", headers=ADMIN, json={"sensitive_keywords": ["Employee id"]})
    assert r.json()["settings"]["sensitive_keywords"] == ["Employee id"]


def test_settings_apply_to_requests(client, make_key):
    h = make_key(["mask"])
    client.put("/v1/admin/settings", headers=ADMIN, json={"enabled_types": ["PHONE_NUMBER"], "keywords_enabled": False})
    r = client.post("/v1/mask", headers=h, json={"text": "a@b.com, Salary: 10. Call +91 98765 43210."})
    assert r.json()["text"] == "a@b.com, Salary: 10. Call <PHONE_NUMBER>."


def test_custom_types(client, make_key):
    h = make_key(["mask"])
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


def test_keys_lifecycle(client):
    r = client.post("/v1/admin/keys", headers=ADMIN, json={"name": "billing", "permissions": ["mask"]})
    assert r.status_code == 201
    info, key = r.json(), r.json()["key"]
    assert key.startswith("pii_") and info["rate_limit"] == 120
    listed = client.get("/v1/admin/keys", headers=ADMIN).json()
    assert any(k["name"] == "billing" for k in listed) and all("key" not in k and "key_hash" not in k for k in listed)
    assert client.post("/v1/admin/keys", headers=ADMIN, json={"name": "billing", "permissions": ["mask"]}).status_code == 409
    assert client.post("/v1/admin/keys", headers=ADMIN, json={"name": "y", "permissions": ["fly"]}).status_code == 400
    h = {"Authorization": f"Bearer {key}"}
    assert client.post("/v1/mask", headers=h, json={"text": "hi"}).status_code == 200
    client.patch(f"/v1/admin/keys/{info['id']}", headers=ADMIN, json={"permissions": ["admin"]})
    assert client.post("/v1/mask", headers=h, json={"text": "hi"}).status_code == 403
    assert client.delete(f"/v1/admin/keys/{info['id']}", headers=ADMIN).json()["active"] is False
    assert client.post("/v1/mask", headers=h, json={"text": "hi"}).status_code == 401



def test_admin_needs_admin(client, make_key):
    assert client.get("/v1/admin/settings", headers=make_key(["mask"])).status_code == 403


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


def test_audit_log_lists_calls_with_counts(client, make_key):
    h = make_key(["mask"])
    client.post("/v1/mask", headers=h, json={"text": "Mail x.y@corp.com"})
    log = client.get("/v1/admin/audit", headers=ADMIN, params={"operation": "mask", "limit": 5}).json()
    assert log and log[0]["counts"] == {"EMAIL_ADDRESS": 1} and "scope" not in log[0]
