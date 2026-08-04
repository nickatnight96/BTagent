"""Readiness must mean "this pod can serve requests", not "the process is up".

Two endpoints, two jobs, and the chart used to point both probes at the same
one:

* ``/health`` is **liveness** and deliberately never returns non-2xx. A
  transient DB blip must not get the container killed — a restart fixes
  nothing and drops in-flight work. It reports ``"database": "unreachable"``
  in the body and still answers 200.
* ``/health/ready`` is **readiness** and 503s when a gating dependency is
  down, so Kubernetes stops routing to a pod that would only serve errors.

With ``readinessProbe`` on ``/health``, readiness meant no more than "the
process is listening": a pod that could not reach Postgres stayed in the
Service and 500'd every request it was handed. That is the defect these tests
hold closed, from both ends — the endpoint's gating semantics, and the chart
actually pointing at it.

The S3 half is the part worth reading carefully. Moving readiness to
``/health/ready`` would, on its own, have made a MinIO blip pull every backend
pod out of the Service — to protect evidence storage, which does not exist.
So ``s3`` is reported but does not gate, and
``test_s3_stays_non_gating_only_while_nothing_uploads`` ties that decision to
the fact it rests on: the first ``put_object`` in the tree fails the test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_VALUES = _REPO / "infra" / "helm" / "btagent" / "values.yaml"
_HEALTH = _REPO / "backend" / "btagent_backend" / "api" / "v1" / "health.py"

#: Where a real upload would have to appear.
_PRODUCT_TREES = (
    _REPO / "backend" / "btagent_backend",
    _REPO / "agents" / "btagent_agents",
    _REPO / "engine" / "btagent_engine",
)
_UPLOAD_CALLS = re.compile(r"\.(put_object|upload_fileobj|upload_file)\s*\(")


@pytest.fixture(scope="module")
def values() -> dict:
    return yaml.safe_load(_VALUES.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The chart points each probe at the endpoint built for it.
# ---------------------------------------------------------------------------


def test_readiness_probe_uses_the_deep_endpoint(values: dict):
    path = values["readinessProbe"]["httpGet"]["path"]
    assert path == "/health/ready", (
        f"readinessProbe points at {path!r}. /health answers 200 even when the "
        "database is unreachable, so a pod that cannot serve requests would stay "
        "in the Service."
    )


def test_liveness_probe_stays_on_the_shallow_endpoint(values: dict):
    """The mirror-image mistake: killing pods over a transient dependency blip."""
    path = values["livenessProbe"]["httpGet"]["path"]
    assert path == "/health", (
        f"livenessProbe points at {path!r}. /health/ready 503s on a dependency "
        "outage; as a liveness probe that restarts the container, which fixes "
        "nothing and drops in-flight work."
    )


def test_readiness_timeout_covers_the_probes_own_budget(values: dict):
    """Each dependency check is bounded at 3s; the probe must allow for that."""
    src = _HEALTH.read_text(encoding="utf-8")
    match = re.search(r"READINESS_CHECK_TIMEOUT_SECONDS\s*=\s*([\d.]+)", src)
    assert match, "the per-check timeout constant is gone"
    per_check = float(match.group(1))
    assert values["readinessProbe"]["timeoutSeconds"] >= per_check, (
        "kubelet would time the probe out before the endpoint's own bounded "
        "checks finish, turning a slow dependency into a flapping pod"
    )


# ---------------------------------------------------------------------------
# Gating semantics.
# ---------------------------------------------------------------------------


def test_db_and_redis_gate_readiness():
    """The whole point: a pod with a dead dependency leaves the Service."""
    src = _HEALTH.read_text(encoding="utf-8")
    match = re.search(r"all_ok = (.+)", src)
    assert match, "the readiness verdict is no longer a single expression"
    expr = match.group(1)
    assert "db_ok" in expr and "redis_ok" in expr and "revocation_ok" in expr


def test_s3_does_not_gate_today():
    from btagent_backend.api.v1 import health

    assert health.S3_GATES_READINESS is False


def test_s3_stays_non_gating_only_while_nothing_uploads():
    """The fact the decision rests on, asserted rather than assumed.

    ``S3_GATES_READINESS`` is False because object storage is provisioned but
    unused. The moment something uploads, that reasoning expires — so this
    fails on the first upload call and the flag has to be revisited in the
    same change.
    """
    from btagent_backend.api.v1 import health

    uploads: list[str] = []
    for tree in _PRODUCT_TREES:
        for path in tree.rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            for match in _UPLOAD_CALLS.finditer(path.read_text(encoding="utf-8")):
                uploads.append(f"{path.relative_to(_REPO)}: {match.group(0)}")

    if uploads and not health.S3_GATES_READINESS:
        pytest.fail(
            "object storage is now written to, so it is a real dependency — set "
            "S3_GATES_READINESS = True (and update the note in cli/storage.py and "
            "the MinIO section of docs/DEPLOYMENT.md):\n  " + "\n  ".join(uploads)
        )


def test_the_upload_scan_can_actually_find_a_call():
    """Guard the guard — a regex that matches nothing would pass forever."""
    sample = "client.put_object(Bucket='b', Key='k')"
    assert _UPLOAD_CALLS.search(sample)
    assert sum(1 for tree in _PRODUCT_TREES for _ in tree.rglob("*.py")) > 100, (
        "the product trees look empty; the scan paths have probably drifted"
    )


# ---------------------------------------------------------------------------
# Behaviour, against the real app.
# ---------------------------------------------------------------------------


def _stub_checks(monkeypatch, **states: bool) -> None:
    """Pin every dependency check so one variable moves at a time.

    The test environment has no Redis, so ``redis`` and ``revocation`` fail on
    their own. Without pinning them, a test that means "only S3 is down" is
    really "three things are down" and proves nothing about S3.
    """
    from btagent_backend.api.v1 import health

    for name, healthy in states.items():
        # Both bound as defaults: closing over the loop variables would make
        # every stub report the last dependency's name and health.
        async def check(healthy: bool = healthy, name: str = name) -> bool:
            if not healthy:
                raise RuntimeError(f"{name} unreachable")
            return True

        monkeypatch.setattr(health, f"_check_{name}", check)


@pytest.mark.asyncio
async def test_ready_returns_200_when_only_s3_is_down(client, monkeypatch):
    """MinIO down must not take the pod out of the Service — but must be visible."""
    _stub_checks(monkeypatch, db=True, redis=True, revocation=True, s3=False)

    resp = await client.get("/health/ready")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"]["s3"] == "down (not gating)", body["checks"]


@pytest.mark.asyncio
async def test_ready_returns_503_when_the_database_is_down(client, monkeypatch):
    """Everything else healthy, so the 503 is attributable to the database."""
    _stub_checks(monkeypatch, db=False, redis=True, revocation=True, s3=True)

    resp = await client.get("/health/ready")
    assert resp.status_code == 503, resp.text
    body = resp.json()
    assert body["status"] == "not_ready"
    assert body["checks"] == {
        "db": "down",
        "redis": "ok",
        "s3": "ok",
        "revocation": "ok",
    }


@pytest.mark.asyncio
async def test_ready_returns_503_when_redis_is_down(client, monkeypatch):
    """Redis carries the WS event bus and the revocation list — it gates."""
    _stub_checks(monkeypatch, db=True, redis=False, revocation=True, s3=True)

    resp = await client.get("/health/ready")
    assert resp.status_code == 503, resp.text
    assert resp.json()["checks"]["redis"] == "down"


@pytest.mark.asyncio
async def test_ready_returns_200_when_everything_is_healthy(client, monkeypatch):
    """The control: without this, the 503 tests could pass on a broken endpoint."""
    _stub_checks(monkeypatch, db=True, redis=True, revocation=True, s3=True)

    resp = await client.get("/health/ready")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ready"


@pytest.mark.asyncio
async def test_liveness_stays_200_when_the_database_is_down(client, monkeypatch):
    """The property that makes /health wrong for readiness and right for liveness."""
    import btagent_backend.api.v1.health as health

    class _Boom:
        async def __aenter__(self):
            raise RuntimeError("postgres unreachable")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(health, "async_session_factory", lambda: _Boom())

    resp = await client.get("/health")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["database"] == "unreachable"
    assert body["status"] == "degraded"
