"""Health and readiness endpoints.

Two distinct probes serve two distinct purposes:

* ``GET /health`` — **liveness**. Fast, dependency-light. Returns 200 whenever
  the process is up so orchestrators / CI startup gates (``curl --fail
  http://localhost:8000/health``) never block on downstream infra. It performs
  only a cheap local DB probe and *never* returns a non-2xx status: a failing
  DB is surfaced as ``status: degraded`` with a 200 so a transient DB blip does
  not flap the liveness signal. It deliberately does **not** touch Redis or
  S3/MinIO.
* ``GET /health/ready`` — **readiness**. Concurrently verifies DB, Redis and
  S3/MinIO with short per-check timeouts and returns 503 (with a per-dependency
  body) when any dependency is unhealthy. Use this for rollout gating /
  load-balancer readiness — NOT for the cheap CI liveness curl, and not in
  environments (such as CI) that have no MinIO.
"""

import asyncio
import logging

from fastapi import APIRouter, Response
from sqlalchemy import text

from btagent_backend.config import get_settings
from btagent_backend.db.engine import async_session_factory

logger = logging.getLogger("btagent.health")

router = APIRouter()

# Per-dependency probe timeout (seconds). Kept short so a hung dependency can
# never make the readiness probe itself hang — each check is independently
# bounded and reported.
READINESS_CHECK_TIMEOUT_SECONDS = 3.0


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe — fast, always 200 when the process is up.

    Performs a single cheap local DB probe but never returns a non-2xx status
    and never touches Redis or S3/MinIO, so it is safe as a CI / orchestrator
    startup gate.
    """
    settings = get_settings()
    status = {"status": "ok", "env": settings.env, "version": "0.1.0"}

    # DB check — cheap local probe. A failure degrades the body but keeps 200
    # so liveness does not flap on a transient DB blip.
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        status["database"] = "connected"
    except Exception:
        # SEC-004 FIX: Do not leak exception details in health endpoint response
        status["database"] = "unreachable"
        status["status"] = "degraded"

    # Redis is intentionally not probed here — liveness must stay shallow.
    status["redis"] = "not_configured"

    return status


async def _check_db() -> bool:
    """Return True if a ``SELECT 1`` succeeds against the async DB engine."""
    async with async_session_factory() as session:
        await session.execute(text("SELECT 1"))
    return True


async def _check_redis() -> bool:
    """Return True if Redis answers PING. Closes the probe client afterwards."""
    from redis.asyncio import Redis

    settings = get_settings()
    client = Redis.from_url(settings.redis_url, decode_responses=True)
    try:
        await client.ping()
        return True
    finally:
        await client.aclose()


def _head_bucket_sync() -> None:
    """Blocking ``head_bucket`` against the configured S3/MinIO bucket.

    Run inside a worker thread (boto3 is synchronous) and wrapped in an asyncio
    timeout by the caller so it can never hang the probe.
    """
    import boto3
    from botocore.config import Config

    settings = get_settings()
    # Short connect/read timeouts and no retries so a dead endpoint fails fast
    # rather than burning the whole readiness budget on boto3's default retries.
    client = boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(
            connect_timeout=2,
            read_timeout=2,
            retries={"max_attempts": 0},
        ),
    )
    client.head_bucket(Bucket=settings.s3_bucket)


async def _check_s3() -> bool:
    """Return True if the configured S3/MinIO bucket is reachable."""
    await asyncio.to_thread(_head_bucket_sync)
    return True


async def _check_revocation() -> bool:
    """Return True if the token-revocation list is on Redis (not fail-open).

    B4: a revocation list running on the in-memory fallback means revoked
    tokens work again in other workers — an operator-visible readiness
    condition. The probe also actively re-connects, so readiness doubles as
    heal.
    """
    from btagent_backend.auth import revocation

    return await revocation.check_health()


async def _run_check(coro) -> bool:
    """Run a single dependency check with a bounded timeout.

    Returns the check's boolean result; False on any failure (including
    timeout). Never raises so one failing dependency cannot abort the others.
    """
    try:
        return bool(await asyncio.wait_for(coro, timeout=READINESS_CHECK_TIMEOUT_SECONDS))
    except Exception as exc:  # noqa: BLE001 — readiness must never raise
        logger.warning("readiness check failed: %s", exc)
        return False


#: Whether a failing S3/MinIO check should take the pod out of the Service.
#:
#: ``False`` today, and the reason is narrow and checkable: **nothing in the
#: product writes to object storage.** There is no ``put_object`` /
#: ``upload_fileobj`` anywhere in backend, agents or engine; ``EvidenceRow``
#: is declared but never inserted; no route serves evidence. The bucket is
#: provisioned by ``bt init-storage`` and head_bucket'd here, and that is the
#: whole of its involvement.
#:
#: So gating readiness on it would mean a MinIO blip pulls every backend pod
#: out of the Service to protect a capability that does not exist — trading a
#: real outage for a hypothetical one. The check still runs and is still
#: reported, because an operator wants to know before evidence storage lands,
#: not after.
#:
#: **Flip this to True in the same change that adds the first upload.**
#: ``test_readiness_gating.py`` fails if an upload call appears while this is
#: still False, so the two cannot drift apart.
S3_GATES_READINESS = False


@router.get("/health/ready")
async def readiness(response: Response) -> dict:
    """Deep readiness probe — verifies DB, Redis, S3/MinIO and revocation.

    Returns 200 with ``{"status": "ready", "checks": {...}}`` when every
    *gating* dependency is healthy; 503 with the same shape
    (``status: not_ready``) when one is down, so the body shows exactly which.
    Each check is independently bounded by ``READINESS_CHECK_TIMEOUT_SECONDS``
    so the probe itself can never hang.

    This is what the Helm chart's ``readinessProbe`` points at. ``/health`` is
    liveness and answers 200 even while reporting ``"database": "unreachable"``
    — pointing readiness there (as the chart used to) means a pod that cannot
    reach Postgres stays in the Service and 500s every request.

    ``s3`` is reported but does not gate; see :data:`S3_GATES_READINESS`.
    """
    db_ok, redis_ok, s3_ok, revocation_ok = await asyncio.gather(
        _run_check(_check_db()),
        _run_check(_check_redis()),
        _run_check(_check_s3()),
        _run_check(_check_revocation()),
    )

    checks = {
        "db": "ok" if db_ok else "down",
        "redis": "ok" if redis_ok else "down",
        "s3": "ok" if s3_ok else ("down" if S3_GATES_READINESS else "down (not gating)"),
        "revocation": "ok" if revocation_ok else "degraded",
    }
    all_ok = db_ok and redis_ok and revocation_ok and (s3_ok or not S3_GATES_READINESS)

    if not all_ok:
        response.status_code = 503

    return {"status": "ready" if all_ok else "not_ready", "checks": checks}
