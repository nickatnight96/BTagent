"""Async SQLAlchemy engine and session factory."""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from starlette.requests import HTTPConnection

from btagent_backend.config import get_settings
from btagent_backend.middleware.commit_before_response import DB_SESSION_STATE_KEY


def create_engine():
    """Create async database engine from settings."""
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        echo=settings.db_echo,
    )


engine = create_engine()
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session(request: HTTPConnection) -> AsyncSession:
    """Dependency: yield an async DB session with automatic cleanup.

    The session is stashed on ``request.state`` so
    :class:`~btagent_backend.middleware.commit_before_response.CommitBeforeResponseMiddleware`
    can commit it *before* the response is sent — dependency teardown (the
    ``commit()`` below) runs after the client already has the status line,
    which is too late to be the only commit: it let clients race their own
    writes and could never turn a failed commit into an error response. The
    teardown commit stays as a no-op safety net and as the real commit for
    anything that reuses this generator outside the HTTP middleware stack.
    """
    async with async_session_factory() as session:
        # The WS routes drive this generator by hand and pass their
        # WebSocket (an HTTPConnection too); there the stash is inert — no
        # HTTP middleware runs — and the teardown commit below stays the
        # real one, as it always was for WebSockets.
        setattr(request.state, DB_SESSION_STATE_KEY, session)
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
