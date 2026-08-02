"""B13 / P4.6: the Prometheus /metrics scrape is bearer-gated when configured.

The endpoint was reachable by anyone who could hit the directly-published
:8000 (compose exposes the port; nginx doesn't proxy /metrics). When
``BTAGENT_METRICS_TOKEN`` is set it now requires a matching bearer token;
unset keeps the open dev/compose default.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from btagent_backend.config import get_settings


@pytest.mark.asyncio
async def test_metrics_open_when_token_unset(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("BTAGENT_METRICS_TOKEN", "")
    get_settings.cache_clear()
    try:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "btagent_" in resp.text
    finally:
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_metrics_requires_bearer_when_token_set(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("BTAGENT_METRICS_TOKEN", "s3cret-scrape")
    get_settings.cache_clear()
    try:
        # No / wrong token → 401.
        assert (await client.get("/metrics")).status_code == 401
        bad = await client.get("/metrics", headers={"Authorization": "Bearer nope"})
        assert bad.status_code == 401

        # Correct token → 200.
        ok = await client.get("/metrics", headers={"Authorization": "Bearer s3cret-scrape"})
        assert ok.status_code == 200
        assert "btagent_" in ok.text
    finally:
        get_settings.cache_clear()
