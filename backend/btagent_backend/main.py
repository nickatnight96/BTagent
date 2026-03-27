"""BTagent FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from btagent_backend.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize and cleanup resources."""
    settings = get_settings()

    # TODO: Initialize Redis connection pool
    # TODO: Initialize WebSocket hub
    # TODO: Initialize TaskManager (auto-resume investigations)
    # TODO: Initialize OTEL if enabled

    yield

    # TODO: Graceful shutdown — checkpoint running investigations
    # TODO: Close Redis pool
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

    # TODO: Mount WebSocket endpoints
    # TODO: Add request ID middleware
    # TODO: Add error handler middleware

    return app


app = create_app()
