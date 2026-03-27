"""Prometheus custom metrics for BTagent.

All metrics are registered once at module import and exposed via a ``/metrics``
endpoint that Prometheus scrapes.
"""

from __future__ import annotations

from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.requests import Request
from starlette.responses import Response

# ── Investigation metrics ──────────────────────────────────────────────────
investigation_count = Counter(
    "btagent_investigation_count",
    "Total investigations created",
    ["status", "severity"],
)

investigation_duration = Histogram(
    "btagent_investigation_duration_seconds",
    "Wall-clock seconds from investigation creation to close",
    buckets=(60, 300, 600, 1800, 3600, 7200, 14400, 28800, 86400),
)

# ── Agent metrics ──────────────────────────────────────────────────────────
agent_invocations = Counter(
    "btagent_agent_invocations_total",
    "Total agent invocations",
    ["agent_type", "status"],
)

# ── LLM metrics ───────────────────────────────────────────────────────────
llm_tokens_total = Counter(
    "btagent_llm_tokens_total",
    "Cumulative LLM token usage",
    ["model", "type"],  # type = input | output
)

llm_cost_total = Counter(
    "btagent_llm_cost_usd_total",
    "Cumulative LLM cost in USD",
    ["model"],
)

# ── HITL metrics ──────────────────────────────────────────────────────────
hitl_checkpoints = Counter(
    "btagent_hitl_checkpoints_total",
    "Human-in-the-loop checkpoint decisions",
    ["action"],  # approve | reject
)

# ── Webhook metrics ───────────────────────────────────────────────────────
webhook_received = Counter(
    "btagent_webhook_received_total",
    "Inbound webhook events",
    ["source"],  # splunk | cs | sentinel | elastic
)

# ── WebSocket metrics ─────────────────────────────────────────────────────
ws_connections_active = Gauge(
    "btagent_ws_connections_active",
    "Current number of active WebSocket connections",
)


# ── /metrics endpoint ─────────────────────────────────────────────────────
async def metrics_endpoint(request: Request) -> Response:
    """Prometheus scrape endpoint.

    Mount this on the FastAPI app as ``app.add_route("/metrics", metrics_endpoint)``.
    """
    body = generate_latest(REGISTRY)
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
