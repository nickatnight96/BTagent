"""Health check endpoint."""

from fastapi import APIRouter
from sqlalchemy import text

from btagent_backend.config import get_settings
from btagent_backend.db.engine import async_session_factory

router = APIRouter()


@router.get("/health")
async def health():
    """Health check with DB and Redis connectivity status."""
    settings = get_settings()
    status = {"status": "ok", "env": settings.env, "version": "0.1.0"}

    # DB check
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        status["database"] = "connected"
    except Exception:
        # SEC-004 FIX: Do not leak exception details in health endpoint response
        status["database"] = "unreachable"
        status["status"] = "degraded"

    # Redis check (TODO: implement when Redis client is initialized)
    status["redis"] = "not_configured"

    return status
