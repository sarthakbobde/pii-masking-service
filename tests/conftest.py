import os
import tempfile

from cryptography.fernet import Fernet

_tmp = tempfile.mkdtemp(prefix="pii-tests-")
os.environ["PII_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["PII_MASTER_KEY"] = Fernet.generate_key().decode()
os.environ["PII_BOOTSTRAP_ADMIN_KEY"] = "test-admin-key-0123456789abcdef"
os.environ["PII_WARM_UP"] = "false"
os.environ.pop("PII_SETTINGS_FILE", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import auth, policy  # noqa: E402
from app.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer " + os.environ["PII_BOOTSTRAP_ADMIN_KEY"]}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _fresh(client):
    """Default settings, the starter fields and empty rate-limit windows for every test."""
    auth.reset()
    client.put("/v1/admin/settings", headers=ADMIN, json=policy.defaults())
    for t in client.get("/v1/admin/custom-types", headers=ADMIN).json():
        client.delete(f"/v1/admin/custom-types/{t['id']}", headers=ADMIN)
    for f in client.get("/v1/admin/fields", headers=ADMIN).json():
        client.delete(f"/v1/admin/fields/{f['id']}", headers=ADMIN)
    for f in policy.STARTER_FIELDS:
        client.post("/v1/admin/fields", headers=ADMIN, json=f)
    policy.invalidate()
    yield
    auth.reset()


_n = 0


@pytest.fixture
def make_key(client):
    """make_key(["mask"], ["team-a"], rate_limit=None) -> request headers for a new key."""
    def make(permissions, scopes=("team-a",), rate_limit=None):
        global _n
        _n += 1
        r = client.post("/v1/admin/keys", headers=ADMIN, json={"name": f"svc-{_n}", "permissions": list(permissions),
                                                               "scopes": list(scopes), "rate_limit": rate_limit})
        assert r.status_code == 201, r.text
        return {"X-API-Key": r.json()["key"]}
    return make
