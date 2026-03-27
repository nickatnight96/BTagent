"""Sprint 1 UAT — verify all deliverables work end-to-end.

Run with: pytest tests/uat/test_sprint1_uat.py -v
Requires: backend running on localhost:8000, postgres + redis up
"""

import httpx
import pytest

BASE = "http://localhost:8000"


@pytest.fixture(scope="module")
def client():
    return httpx.Client(base_url=BASE, timeout=10)


@pytest.fixture(scope="module")
def admin_token(client):
    """Login as admin and return access token."""
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200, f"Admin login failed: {r.text}"
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    return data["access_token"]


@pytest.fixture(scope="module")
def analyst_token(client):
    """Login as analyst and return access token."""
    r = client.post("/api/v1/auth/login", json={"username": "analyst1", "password": "analyst1"})
    assert r.status_code == 200, f"Analyst login failed: {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


# ── UAT-HEALTH: Health endpoint ──────────────────────────
class TestHealth:
    def test_health_returns_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"
        assert data["database"] == "connected"


# ── UAT-AUTH: Authentication ─────────────────────────────
class TestAuth:
    def test_login_valid_credentials(self, client):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self, client):
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_login_nonexistent_user(self, client):
        r = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "ghost"})
        assert r.status_code == 401

    def test_me_with_valid_token(self, client, admin_token):
        r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    def test_me_without_token(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code in (401, 403)  # No Authorization header

    def test_me_with_invalid_token(self, client):
        r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
        assert r.status_code == 401

    def test_refresh_token(self, client):
        # Login to get refresh token
        r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        refresh_token = r.json()["refresh_token"]

        # Use refresh token to get new pair
        r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data


# ── UAT-RBAC: Role-based access control ──────────────────
class TestRBAC:
    def test_admin_can_register_user(self, client, auth_headers):
        import time

        username = f"uat_test_{int(time.time())}"
        r = client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"{username}@btagent.local",
                "password": "test123",
                "role": "analyst",
            },
            headers=auth_headers,
        )
        assert r.status_code == 201
        data = r.json()
        assert data["username"] == username
        assert data["role"] == "analyst"

    def test_analyst_cannot_register_user(self, client, analyst_headers):
        r = client.post(
            "/api/v1/auth/register",
            json={
                "username": "should_fail",
                "email": "fail@btagent.local",
                "password": "test123",
                "role": "analyst",
            },
            headers=analyst_headers,
        )
        assert r.status_code in (401, 403)  # Permission denied

    def test_duplicate_registration_rejected(self, client, auth_headers):
        r = client.post(
            "/api/v1/auth/register",
            json={
                "username": "admin",
                "email": "admin@btagent.local",
                "password": "test123",
                "role": "analyst",
            },
            headers=auth_headers,
        )
        assert r.status_code == 409  # Conflict


# ── UAT-INVESTIGATIONS: CRUD + lifecycle ─────────────────
class TestInvestigations:
    investigation_id = None

    def test_create_investigation(self, client, analyst_headers):
        r = client.post(
            "/api/v1/investigations",
            json={
                "title": "UAT Phishing Alert",
                "description": "Test phishing investigation for UAT",
                "severity": "high",
                "tlp_level": "amber",
            },
            headers=analyst_headers,
        )
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "UAT Phishing Alert"
        assert data["severity"] == "high"
        assert data["tlp_level"] == "amber"
        assert data["status"] == "pending"
        assert data["id"].startswith("inv_")
        TestInvestigations.investigation_id = data["id"]

    def test_list_investigations(self, client, analyst_headers):
        r = client.get("/api/v1/investigations", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        assert data["page"] == 1

    def test_list_with_pagination(self, client, analyst_headers):
        r = client.get("/api/v1/investigations?page=1&page_size=1", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["page_size"] == 1
        assert len(data["items"]) == 1

    def test_get_investigation_detail(self, client, analyst_headers):
        inv_id = TestInvestigations.investigation_id
        r = client.get(f"/api/v1/investigations/{inv_id}", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == inv_id
        assert data["title"] == "UAT Phishing Alert"

    def test_get_nonexistent_investigation(self, client, analyst_headers):
        r = client.get("/api/v1/investigations/inv_nonexistent", headers=analyst_headers)
        assert r.status_code == 404

    def test_chat_sends_message(self, client, analyst_headers):
        inv_id = TestInvestigations.investigation_id
        r = client.post(
            f"/api/v1/investigations/{inv_id}/chat",
            json={"message": "Analyze the suspicious login from 192.168.1.100"},
            headers=analyst_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "sent"

    def test_stop_investigation(self, client, auth_headers):
        """Admin/senior can stop investigation."""
        inv_id = TestInvestigations.investigation_id
        r = client.post(f"/api/v1/investigations/{inv_id}/stop", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "cancelled"

    def test_list_with_status_filter(self, client, analyst_headers):
        r = client.get("/api/v1/investigations?status=cancelled", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        assert all(item["status"] == "cancelled" for item in data["items"])


# ── UAT-UNAUTHENTICATED: Verify protection ──────────────
class TestUnauthenticated:
    def test_investigations_requires_auth(self, client):
        r = client.get("/api/v1/investigations")
        assert r.status_code in (401, 403)

    def test_create_requires_auth(self, client):
        r = client.post("/api/v1/investigations", json={"title": "No auth"})
        assert r.status_code in (401, 403)

    def test_health_does_not_require_auth(self, client):
        r = client.get("/health")
        assert r.status_code == 200


# ── UAT-SHARED-TYPES: Verify type system ─────────────────
class TestSharedTypes:
    def test_id_generation(self):
        from btagent_shared.utils.ids import generate_id

        inv_id = generate_id("inv")
        assert inv_id.startswith("inv_")
        assert len(inv_id) > 10

        ioc_id = generate_id("ioc")
        assert ioc_id.startswith("ioc_")
        assert inv_id != ioc_id  # Unique

    def test_event_envelope(self):
        from btagent_shared.types import EventEnvelope, EventType

        evt = EventEnvelope(
            type=EventType.IOC_DISCOVERED,
            investigation_id="inv_test",
            data={"ioc_type": "ip", "value": "10.0.0.1"},
        )
        assert evt.id.startswith("evt_")
        assert evt.type == "ioc_discovered"
        assert evt.timestamp  # Auto-generated

    def test_investigation_model(self):
        from btagent_shared.types import Investigation, Severity, TLP

        inv = Investigation(
            id="inv_test",
            title="Test",
            severity=Severity.CRITICAL,
            tlp_level=TLP.RED,
        )
        assert inv.severity == "critical"
        assert inv.status == "pending"

    def test_agent_config_defaults(self):
        from btagent_shared.types import AgentConfig

        config = AgentConfig(investigation_id="inv_test")
        assert config.model_provider == "anthropic"
        assert config.max_tokens == 80_000
        assert config.max_cost_usd == 5.0
        assert config.autonomy_level == "L2"
