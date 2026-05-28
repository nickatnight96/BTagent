"""BTagent FastAPI application factory."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from btagent_backend.config import get_settings
from btagent_backend.middleware.request_id import RequestIDMiddleware
from btagent_backend.middleware.security_headers import SecurityHeadersMiddleware
from btagent_backend.observability import metrics_endpoint, setup_logging, setup_otel, shutdown_otel
from btagent_backend.services.task_manager import TaskManager
from btagent_backend.ws import WebSocketHub, init_ws_routes, ws_router

logger = logging.getLogger("btagent.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize and cleanup resources."""
    settings = get_settings()

    # Structured JSON logging (must be first so all subsequent logs are JSON)
    setup_logging(settings)

    # OpenTelemetry tracing + metrics (graceful when collector unreachable)
    setup_otel(app, settings)

    # Initialize WebSocket hub (Redis pub/sub + connection management)
    hub = WebSocketHub(redis_url=settings.redis_url)
    await hub.start()
    init_ws_routes(hub)
    app.state.ws_hub = hub
    logger.info("WebSocket hub initialised")

    # EPIC-7 UC-7.2: forward every refused TLP egress to the event bus as a
    # real-time ``tlp.violation_attempt`` alert. The shared gate calls the
    # sink; we bridge it to the WebSocket hub here.
    from btagent_shared.security.tlp_policy import set_violation_sink

    from btagent_backend.services.tlp_alert_sink import make_tlp_violation_sink

    set_violation_sink(make_tlp_violation_sink(hub))
    logger.info("TLP violation alerter wired to WebSocket hub")

    # Register the live LLM client unless running in mock mode. In dev
    # (BTAGENT_MOCK_LLM defaults to "true") this is skipped and the engine's
    # reasoning nodes use their deterministic mock path. In a real deployment
    # (BTAGENT_MOCK_LLM=false + provider keys) the LiteLLM-backed client is
    # registered so engine nodes dispatch to real providers.
    import os

    if os.getenv("BTAGENT_MOCK_LLM", "true").lower() != "true":
        try:
            from btagent_agents.llm.client import LiteLLMClient
            from btagent_engine.llm import set_llm_client

            set_llm_client(LiteLLMClient())
            logger.info("Live LLM client registered (LiteLLM router)")
        except Exception:  # noqa: BLE001 - never let LLM wiring block startup
            logger.exception("Failed to register live LLM client; nodes will raise on dispatch")

    # Initialize TaskManager and auto-resume active investigations
    task_manager = TaskManager(
        redis_url=settings.redis_url,
        database_url=settings.database_url,
    )
    app.state.task_manager = task_manager
    resumed = await task_manager.auto_resume()
    logger.info("TaskManager initialised (auto-resumed %d investigation(s))", resumed)

    yield

    # Graceful shutdown — checkpoint running investigations
    await task_manager.shutdown()
    logger.info("TaskManager shut down")

    # Graceful shutdown — stop WebSocket hub (notifies clients, closes Redis)
    from btagent_shared.security.tlp_policy import clear_violation_sink

    clear_violation_sink()
    await hub.stop()
    logger.info("WebSocket hub shut down")

    # Flush OTEL spans/metrics
    await shutdown_otel()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="BTagent",
        description="Defensive Cyber Security AI Agent — Incident Response & Threat Hunting",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.env != "prod" else None,
        redoc_url="/api/redoc" if settings.env != "prod" else None,
    )

    # AUTH-C1: cookie auth requires ``allow_credentials=True``, which in turn
    # requires ``allow_origins`` to be an explicit list — the browser refuses
    # to send cookies when CORS allows ``*``. Fail loudly at startup if the
    # config drifts to a wildcard so the misconfiguration is caught in
    # staging, not in production.
    if "*" in settings.cors_origins:
        raise RuntimeError(
            "BTAGENT_CORS_ORIGINS must be an explicit list (no '*') because "
            "cookie-based auth requires allow_credentials=True."
        )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )

    # Request-ID middleware (adds X-Request-ID to every request/response)
    app.add_middleware(RequestIDMiddleware)

    # Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    # Referrer-Policy, Permissions-Policy). Idempotent with the production
    # nginx ingress so the backend can stand alone in dev / helm-without-
    # nginx topologies.
    app.add_middleware(SecurityHeadersMiddleware)

    # Mount routers
    from btagent_backend.api.v1.router import api_v1_router, health_router_root

    app.include_router(health_router_root)
    app.include_router(api_v1_router)

    # Mount WebSocket endpoints
    app.include_router(ws_router)

    # Prometheus metrics scrape endpoint
    app.add_route("/metrics", metrics_endpoint)

    return app


app = create_app()
