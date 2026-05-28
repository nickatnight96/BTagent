"""Shared test fixtures for BTagent backend test suite.

Sets up an in-memory SQLite async database, intercepts the PostgreSQL engine
module, overrides FastAPI dependencies, and provides pre-built users, tokens,
and investigations for all tests.
"""

import hashlib
import json
import os
import sys
import types
from datetime import UTC, datetime

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import JSON, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ============================================================================
# Phase 1 — Environment + engine interception (must run before ANY backend
#            module is imported, because db/engine.py eagerly creates a PG
#            engine at import time).
# ============================================================================
os.environ["BTAGENT_TEST_MODE"] = "true"
os.environ["BTAGENT_ENV"] = "test"
os.environ["BTAGENT_JWT_SECRET"] = "test-secret-key-for-jwt-signing-only"
os.environ["BTAGENT_DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["BTAGENT_RATE_LIMIT_ENABLED"] = "true"

# Build the test SQLite engine before the backend can try to reach PostgreSQL.
_test_engine = create_async_engine(
    "sqlite+aiosqlite://",
    echo=False,
    connect_args={"check_same_thread": False},
)

_test_session_factory = async_sessionmaker(
    _test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def _test_get_session():
    """Replacement for ``btagent_backend.db.engine.get_session``."""
    async with _test_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# Inject a synthetic ``btagent_backend.db.engine`` module so every
# ``from btagent_backend.db.engine import ...`` resolves to our test objects.
_fake_engine_mod = types.ModuleType("btagent_backend.db.engine")
_fake_engine_mod.__package__ = "btagent_backend.db"
_fake_engine_mod.engine = _test_engine
_fake_engine_mod.async_session_factory = _test_session_factory
_fake_engine_mod.create_engine = lambda: _test_engine
_fake_engine_mod.get_session = _test_get_session
sys.modules["btagent_backend.db.engine"] = _fake_engine_mod

# ============================================================================
# Phase 2 — Now it is safe to import backend code.
# ============================================================================
from btagent_backend.config import get_settings  # noqa: E402

get_settings.cache_clear()

# Force registration of every Base subclass with ``Base.metadata`` BEFORE the
# JSONB → JSON swap below. Importing ``btagent_backend.db.models`` alone only
# registers the four core tables; ``models_knowledge``, ``models_mitre``, and
# ``models_playbook`` define their own tables and only join the metadata
# registry when their modules are imported. Without these side-effect
# imports, their JSONB columns survive untouched and SQLite chokes on them
# at table-creation time (``JSONB cannot render in SQLite``).
import btagent_backend.db.models_behavioral  # noqa: E402, F401
import btagent_backend.db.models_hunt  # noqa: E402, F401
import btagent_backend.db.models_knowledge  # noqa: E402, F401
import btagent_backend.db.models_mfa  # noqa: E402, F401
import btagent_backend.db.models_mitre  # noqa: E402, F401
import btagent_backend.db.models_playbook  # noqa: E402, F401
import btagent_backend.db.models_workflow  # noqa: E402, F401
from btagent_backend.db.models import Base  # noqa: E402

# PostgreSQL JSONB columns are incompatible with SQLite — swap to plain JSON.
for _table in Base.metadata.tables.values():
    for _col in _table.columns:
        if isinstance(_col.type, JSONB):
            _col.type = JSON()
    # PG-specific indexes (GIN, HNSW, expression-based to_tsvector, etc.)
    # cannot be rendered by SQLite. Drop any index that opts into a
    # postgresql-specific feature; production PG schemas still create them
    # via Alembic, but the in-memory test schema is built from
    # ``Base.metadata.create_all`` which can't translate them.
    _pg_only_indexes = [
        idx
        for idx in _table.indexes
        if any(idx.dialect_options.get("postgresql", {}).get(k) for k in ("using", "with", "ops"))
    ]
    for _idx in _pg_only_indexes:
        _table.indexes.discard(_idx)


# Turn on foreign-key enforcement for SQLite (off by default).
@event.listens_for(_test_engine.sync_engine, "connect")
def _enable_sqlite_fk(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# ============================================================================
# Phase 3 — Fixtures
# ============================================================================

# --- Database setup / teardown ---


@pytest_asyncio.fixture(scope="session")
async def _init_db():
    """Create all tables once for the entire test session.

    Also seeds the default organization row required by the org-scoping FK
    constraint added in migration ``0006_org_scoping``.
    """
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed the default org so user/investigation/ioc/evidence FK checks pass.
    from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow

    async with _test_session_factory() as session:
        existing = await session.get(OrganizationRow, DEFAULT_ORG_ID)
        if existing is None:
            session.add(
                OrganizationRow(
                    id=DEFAULT_ORG_ID,
                    name="Default Organization",
                    created_at=datetime.now(UTC),
                )
            )
            await session.commit()

    yield
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await _test_engine.dispose()


@pytest_asyncio.fixture()
async def sample_org(_init_db, db_session: "AsyncSession"):
    """Return the seeded default organization row.

    Tests that need an explicit org reference can depend on this fixture; the
    underlying row is created in ``_init_db`` so any fixture / test that
    inserts an org-scoped row already has a valid FK target.
    """
    from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow

    return await db_session.get(OrganizationRow, DEFAULT_ORG_ID)


@pytest_asyncio.fixture()
async def db_session(_init_db):
    """Yield an async DB session.  Rolls back after each test for isolation."""
    async with _test_session_factory() as session:
        yield session
        await session.rollback()


# --- FastAPI test client ---


@pytest_asyncio.fixture()
async def client(_init_db):
    """``httpx.AsyncClient`` wired to the FastAPI app via ASGI transport."""
    # Patch the health endpoint's direct import of async_session_factory
    # (it uses it to run a quick ``SELECT 1`` DB probe).
    import btagent_backend.api.v1.health as health_mod

    health_mod.async_session_factory = _test_session_factory

    from btagent_backend.api.deps import get_db
    from btagent_backend.main import create_app

    test_app = create_app()
    test_app.dependency_overrides[get_db] = _test_get_session

    # Mock TaskManager on app.state so investigation endpoints don't return 503
    from unittest.mock import AsyncMock, MagicMock

    mock_tm = MagicMock()
    mock_tm.start_investigation = AsyncMock()
    mock_tm.send_message = AsyncMock()
    mock_tm.pause_investigation = AsyncMock()
    mock_tm.resume_investigation = AsyncMock()
    mock_tm.stop_investigation = AsyncMock()
    mock_tm.get_status = MagicMock(
        return_value={"running": 0, "total_started": 0, "agents_available": True}
    )
    test_app.state.task_manager = mock_tm

    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# --- Users ---

from btagent_shared.types.enums import InvestigationStatus, Severity  # noqa: E402
from btagent_shared.utils.ids import generate_id  # noqa: E402

from btagent_backend.auth.jwt import create_token_pair, hash_password  # noqa: E402
from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, UserRow  # noqa: E402

_ADMIN_PASSWORD = "Admin-P@ss-123!"
_ANALYST_PASSWORD = "Analyst-P@ss-456!"

# Counter to guarantee unique usernames/emails across fixture invocations
# within the same test session (in-memory SQLite persists data).
import itertools as _itertools  # noqa: E402

_user_counter = _itertools.count(1)


@pytest_asyncio.fixture()
async def sample_user(db_session: AsyncSession):
    """Create and return a test analyst user (unique per invocation)."""
    n = next(_user_counter)
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"testanalyst_{n}",
        email=f"analyst_{n}@btagent.test",
        password_hash=hash_password(_ANALYST_PASSWORD),
        role="analyst",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest_asyncio.fixture()
async def admin_user(db_session: AsyncSession):
    """Create and return a test admin user (unique per invocation)."""
    n = next(_user_counter)
    user = UserRow(
        id=generate_id("usr"),
        org_id=DEFAULT_ORG_ID,
        username=f"testadmin_{n}",
        email=f"admin_{n}@btagent.test",
        password_hash=hash_password(_ADMIN_PASSWORD),
        role="admin",
        created_at=datetime.now(UTC),
    )
    db_session.add(user)
    await db_session.commit()
    return user


# --- Tokens ---


@pytest_asyncio.fixture()
async def analyst_token(sample_user: UserRow) -> str:
    """Valid JWT access token for the analyst user."""
    return create_token_pair(sample_user.id, sample_user.username, sample_user.role).access_token


@pytest_asyncio.fixture()
async def admin_token(admin_user: UserRow) -> str:
    """Valid JWT access token for the admin user."""
    return create_token_pair(admin_user.id, admin_user.username, admin_user.role).access_token


# --- Sample investigation ---


@pytest_asyncio.fixture()
async def sample_investigation(db_session: AsyncSession, sample_user: UserRow):
    """Create and return a test investigation in INVESTIGATING status."""
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Test Phishing Investigation",
        description="Automated test investigation for unit tests",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    return inv


# ============================================================================
# Helpers importable by test modules (``from conftest import auth_header``)
# ============================================================================


def auth_header(token: str) -> dict[str, str]:
    """Build an ``Authorization: Bearer <token>`` header dict."""
    return {"Authorization": f"Bearer {token}"}


def compute_audit_hash(entry: dict, prev_hash: str = "") -> str:
    """Compute SHA-256 chain hash matching the audit trail logic."""
    canonical = json.dumps(
        {
            "id": entry["id"],
            "seq": entry["seq"],
            "timestamp": entry["timestamp"],
            "actor": entry["actor"],
            "category": entry["category"],
            "action": entry["action"],
            "resource": entry["resource"],
            "outcome": entry["outcome"],
            "prev_hash": prev_hash,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
