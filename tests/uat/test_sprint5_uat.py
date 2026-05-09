"""Sprint 5 UAT -- Observability, notifications, config endpoints.

Run with: pytest tests/uat/test_sprint5_uat.py -v
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
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token(client):
    """Login as analyst and return access token."""
    r = client.post(
        "/api/v1/auth/login", json={"username": "analyst1", "password": "analyst1"}
    )
    assert r.status_code == 200, f"Analyst login failed: {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


# -- UAT-METRICS: Prometheus /metrics endpoint ------------------------------
class TestMetrics:
    def test_metrics_endpoint_exists(self, client):
        """GET /metrics returns prometheus-format text with btagent_ prefixes."""
        r = client.get("/metrics")
        assert r.status_code == 200
        content_type = r.headers.get("content-type", "")
        assert "text/plain" in content_type
        body = r.text
        # Prometheus exposition format should contain at least one btagent_ metric
        assert "btagent_" in body


# -- UAT-REQUEST-ID: X-Request-ID header -----------------------------------
class TestRequestID:
    def test_request_id_header(self, client):
        """Every response should include an X-Request-ID header."""
        r = client.get("/health")
        assert r.status_code == 200
        request_id = r.headers.get("x-request-id")
        assert request_id is not None
        assert len(request_id) > 0

    def test_request_id_echoes_client_value(self, client):
        """If the client sends X-Request-ID, the server echoes it back."""
        custom_id = "uat-test-request-id-12345"
        r = client.get("/health", headers={"X-Request-ID": custom_id})
        assert r.status_code == 200
        assert r.headers.get("x-request-id") == custom_id


# -- UAT-OBSERVABILITY-IMPORTS: Structured logging and OTEL -----------------
class TestObservabilityImports:
    def test_structured_logging_importable(self):
        """setup_logging function is importable from observability.logging."""
        from btagent_backend.observability.logging import setup_logging

        assert callable(setup_logging)

    def test_otel_setup_importable(self):
        """setup_otel function is importable from observability.otel."""
        from btagent_backend.observability.otel import setup_otel

        assert callable(setup_otel)


# -- UAT-SERVICES-IMPORTS: NotificationService and DataRetentionService -----
class TestServiceImports:
    def test_notification_service_importable(self):
        """NotificationService class imports correctly."""
        from btagent_backend.services.notification_service import NotificationService

        assert NotificationService is not None
        # Verify expected methods exist
        assert callable(getattr(NotificationService, "notify_hitl_checkpoint", None))
        assert callable(getattr(NotificationService, "notify_critical_finding", None))
        assert callable(getattr(NotificationService, "send_slack", None))
        assert callable(getattr(NotificationService, "send_inapp", None))

    def test_data_retention_service_importable(self):
        """DataRetentionService class imports correctly."""
        from btagent_backend.services.data_retention import DataRetentionService

        assert DataRetentionService is not None
        assert callable(getattr(DataRetentionService, "archive_old_events", None))
        assert callable(getattr(DataRetentionService, "cleanup_old_investigations", None))
        assert callable(getattr(DataRetentionService, "verify_audit_retention", None))
        assert callable(getattr(DataRetentionService, "get_retention_stats", None))


# -- UAT-ORG-PROFILE: GET and PUT org profile endpoints --------------------
class TestOrgProfile:
    def test_org_profile_get(self, client, analyst_headers):
        """GET /api/v1/config/org-profile returns a profile (or empty default).

        Any authenticated user with config:view can read the profile.
        """
        r = client.get("/api/v1/config/org-profile", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        assert "profile" in data
        assert isinstance(data["profile"], dict)

    def test_org_profile_put(self, client, admin_headers):
        """PUT /api/v1/config/org-profile saves and retrieves (admin only)."""
        profile_data = {
            "org_name": "UAT Test Organisation",
            "industry": "cybersecurity",
            "allowed_domains": ["example.com", "internal.local"],
            "allowed_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
        }
        r = client.put(
            "/api/v1/config/org-profile",
            json=profile_data,
            headers=admin_headers,
        )
        assert r.status_code == 200
        saved = r.json()
        assert "profile" in saved
        assert saved["profile"].get("industry") == "cybersecurity"

        # Verify by re-reading
        r2 = client.get("/api/v1/config/org-profile", headers=admin_headers)
        assert r2.status_code == 200
        fetched = r2.json()
        assert fetched["profile"].get("industry") == "cybersecurity"

    def test_org_profile_put_requires_admin(self, client, analyst_headers):
        """Analyst role cannot PUT org-profile (requires admin -> 403)."""
        r = client.put(
            "/api/v1/config/org-profile",
            json={"org_name": "Should Fail"},
            headers=analyst_headers,
        )
        assert r.status_code == 403


# -- UAT-RETENTION: Data retention stats endpoint --------------------------
class TestRetention:
    def test_retention_stats(self, client, analyst_headers):
        """GET /api/v1/config/retention returns retention statistics."""
        r = client.get("/api/v1/config/retention", headers=analyst_headers)
        assert r.status_code == 200
        data = r.json()
        # The response must have all three sections
        assert "events" in data
        assert "audit_logs" in data
        assert "investigations" in data
        # Events section
        assert "total" in data["events"]
        assert "retention_days" in data["events"]
        # Audit logs section
        assert "total" in data["audit_logs"]
        assert data["audit_logs"]["policy"] == "never_delete"
        # Investigations section
        assert "total" in data["investigations"]


# -- UAT-CONFIG-ROUTER: Config endpoints accessible -------------------------
class TestConfigRouter:
    def test_config_router_mounted(self, client, analyst_headers):
        """Config endpoints should be accessible (not 404).

        Verifies that the config router is properly mounted under /api/v1/config.
        """
        # org-profile GET should be reachable
        r1 = client.get("/api/v1/config/org-profile", headers=analyst_headers)
        assert r1.status_code != 404, "org-profile endpoint returned 404 -- router not mounted"

        # retention GET should be reachable
        r2 = client.get("/api/v1/config/retention", headers=analyst_headers)
        assert r2.status_code != 404, "retention endpoint returned 404 -- router not mounted"
