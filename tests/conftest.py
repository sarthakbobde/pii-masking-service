import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="pii-tests-")
os.environ["PII_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["PII_ADMIN_KEY"] = "test-admin-key-0123456789abcdef"
os.environ["PII_WARM_UP"] = "false"
os.environ.pop("PII_SETTINGS_FILE", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import jobs, policy  # noqa: E402
from app.main import app  # noqa: E402

ADMIN = {"Authorization": "Bearer " + os.environ["PII_ADMIN_KEY"]}


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _fresh(client):
    """Default settings and the starter fields, and no leftover CMS jobs, for every test."""
    client.put("/v1/admin/settings", headers=ADMIN, json=policy.defaults())
    for t in client.get("/v1/admin/custom-types", headers=ADMIN).json():
        client.delete(f"/v1/admin/custom-types/{t['id']}", headers=ADMIN)
    for f in client.get("/v1/admin/fields", headers=ADMIN).json():
        client.delete(f"/v1/admin/fields/{f['id']}", headers=ADMIN)
    for f in policy.STARTER_FIELDS:
        client.post("/v1/admin/fields", headers=ADMIN, json=f)
    policy.invalidate()
    jobs.store.clear()
    yield
