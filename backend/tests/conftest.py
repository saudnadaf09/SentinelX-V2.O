"""API test fixtures: SQLite + in-memory queue/event store (no Docker required)."""
import os
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="sx-tests-")
os.environ.update({
    "APP_ENV": "development", "SECRET_KEY": "test-secret-key-" + "x" * 40,
    "DATABASE_URL": f"sqlite:///{_TMP}/test.db", "QUEUE_BACKEND": "memory", "STORE_BACKEND": "memory",
    "AI_PROVIDER": "disabled", "BOOTSTRAP_ADMIN_PASSWORD": "", "OUTBOX_DIR": _TMP + "/outbox", "MAIL_MODE": "console",
    "ALLOW_REGISTRATION": "true", "REQUIRE_EMAIL_VERIFICATION": "false",
    "RULES_DIR": str(Path(__file__).resolve().parents[2] / "detection-rules"),
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core import container  # noqa: E402
from app.core.ratelimit import limiter  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.session import get_engine, get_session_factory  # noqa: E402
from app.domain.memory_backends import MemoryEventStore, MemoryQueue  # noqa: E402
from app.main import create_app  # noqa: E402
from app.domain.tenancy import DEFAULT_ORG_ID  # noqa: E402
from app.models import Base, Organization, User  # noqa: E402
import uuid  # noqa: E402

PASSWORD = "correct-horse-battery-1"


@pytest.fixture()
def client():
    Base.metadata.drop_all(get_engine())
    Base.metadata.create_all(get_engine())
    container.set_backends(MemoryQueue(), MemoryEventStore())
    container.reset_registry()
    limiter.reset()
    with get_session_factory()() as db:
        db.add(Organization(id=uuid.UUID(DEFAULT_ORG_ID), name="Default Workspace", slug="default-workspace"))
        db.flush()
        for role, stored in (("admin", "super_admin"), ("analyst", "analyst"), ("engineer", "engineer"), ("viewer", "viewer")):
            db.add(User(email=f"{role}@test.local", username=role + "_t", role=stored, org_id=uuid.UUID(DEFAULT_ORG_ID),
                        email_verified=True, password_hash=hash_password(PASSWORD)))
        db.commit()
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def login(client):
    cache = {}

    def _login(role: str) -> dict:
        if role not in cache:
            r = client.post("/api/v1/auth/login", json={"email": f"{role}@test.local", "password": PASSWORD})
            assert r.status_code == 200, r.text
            cache[role] = {"Authorization": f"Bearer {r.json()['access_token']}"}
        return cache[role]
    return _login
