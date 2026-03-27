"""BTagent FastAPI application factory."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from btagent_backend.config import get_settings
from btagent_backend.ws import WebSocketHub, init_ws_routes, ws_router

logger = logging.getLogger("btagent.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize and cleanup resources."""
    settings = get_settings()

    # Initialize WebSocket hub (Redis pub/sub + connection management)
    hub = WebSocketHub(redis_url=settings.redis_url)
    await hub.start()
    init_ws_routes(hub)
    app.state.ws_hub = hub
    logger.info("WebSocket hub initialised")

    # TODO: Initialize TaskManager (auto-resume investigations)
    # TODO: Initialize OTEL if enabled

    yield

    # Graceful shutdown — stop WebSocket hub (notifies clients, closes Redis)
    await hub.stop()
    logger.info("WebSocket hub shut down")

    # TODO: Graceful shutdown — checkpoint running investigations
    # TODO: Close DB engine


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
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routers
    from btagent_backend.api.v1.router import api_v1_router, health_router_root

    app.include_router(health_router_root)
    app.include_router(api_v1_router)

    # Mount WebSocket endpoints
    app.include_router(ws_router)

    # TODO: Add request ID middleware
    # TODO: Add error handler middleware

    return app


app = create_app()
