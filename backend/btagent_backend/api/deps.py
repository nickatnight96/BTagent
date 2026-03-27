"""FastAPI dependency injection."""

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.middleware import CurrentUser, get_current_user
from btagent_backend.db.engine import get_session

# Re-export for clean imports in route handlers
__all__ = ["get_db", "get_current_user", "CurrentUser"]

# Alias for consistency
get_db = get_session
