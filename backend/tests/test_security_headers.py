"""Tests for ``SecurityHeadersMiddleware``.

The middleware is defense-in-depth — it sets HSTS/CSP/X-Frame-Options and
friends so the backend's response posture matches the nginx ingress even
in topologies where the ingress is absent (dev, helm-without-nginx,
internal cluster ingress). The tests pin the policy so future drift
shows up in CI.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_security_headers_present_on_health(client: AsyncClient):
    """Every response should carry the static defense-in-depth headers."""
    resp = await client.get("/health")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "no-referrer"
    assert "Permissions-Policy" in headers

    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


@pytest.mark.asyncio
async def test_hsts_omitted_in_non_prod(client: AsyncClient):
    """``Strict-Transport-Security`` must not be set unless ``BTAGENT_ENV=prod``.

    The test ``client`` fixture runs with ``BTAGENT_ENV=test`` (see
    ``backend/tests/conftest.py``), so HSTS should be absent. Setting it
    over plain HTTP in dev/test would force the browser to upgrade
    ``http://localhost`` to ``https://localhost`` permanently — surprising
    and hard to debug.
    """
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert "Strict-Transport-Security" not in resp.headers


@pytest.mark.asyncio
async def test_csp_allows_websocket_upgrade(client: AsyncClient):
    """``connect-src`` must include ``ws:`` / ``wss:`` so the SPA can open
    the live-event WebSocket without a CSP violation."""
    resp = await client.get("/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "ws:" in csp or "wss:" in csp, (
        "WS upgrade would be blocked by CSP — connect-src missing ws: scheme"
    )
