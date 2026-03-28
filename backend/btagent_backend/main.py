"""BTagent FastAPI application factory."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from btagent_backend.config import get_settings
from btagent_backend.middleware.request_id import RequestIDMiddleware
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

    # Initialize TaskManager and auto-resume active investigations
    task_manager = TaskManager(
        redis_url=settings.redis_url,
        database_url=settings.database_url,
    )
    app.state.task_manager = task_manager
    resumed = await task_manager.auto_resume()
    logger.info(
        "TaskManager initialised (auto-resumed %d investigation(s))", resumed
    )

    yield

    # Graceful shutdown — checkpoint running investigations
    await task_manager.shutdown()
    logger.info("TaskManager shut down")

    # Graceful shutdown — stop WebSocket hub (notifies clients, closes Redis)
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
