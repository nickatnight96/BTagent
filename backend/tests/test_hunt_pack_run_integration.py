"""Tests for the Phase-6 hunt-pack → triage-inbox integration slice (#112).

Covers:
* the pure ``SigmaHit`` → ``HuntFinding`` conversion (mapping goldens, dedupe,
  raw-evidence truncation),
* the scheduled-run service end-to-end against the engine runner's mock
  connectors (run → findings in the DB → suppressed pattern filtered →
  history row with correct counts),
* the suppression-sweep audit-trail behaviour (#119 Phase C item), and
* the ``GET /hunt/pack-runs`` list endpoint (RBAC + org-scope + pagination).
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.types.enums import AuditCategory, Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntPackRunRow, SuppressionRuleRow
from btagent_backend.services import hunt_pack_run_service as prs
from btagent_backend.services import hunt_triage_service as svc

# pysigma + the engine runner are only present in the worker image; skip the
# engine-driven tests cleanly if the stack isn't installed.
engine_runner = pytest.importorskip("btagent_engine.hunting.runner")
engine_pack = pytest.importorskip("btagent_engine.hunting.pack")
SigmaHit = engine_runner.SigmaHit
SigmaHitEntity = engine_runner.SigmaHitEntity


# --------------------------------------------------------------------------- #
# Pure conversion goldens
# --------------------------------------------------------------------------- #


def _hit(**overrides) -> "SigmaHit":
    base = dict(
        source_run_id="hrun_test",
        pack_id="hpack_abc",
        rule_id="rule_1",
        rule_title="Encoded PowerShell",
        backend="splunk",
        severity=Severity.HIGH,
        mitre_techniques=["T1059.001"],
        entities=[SigmaHitEntity(kind="host", value="WS-001")],
        observable="10.1.2.3",
        observable_type="ip",
        summary="powershell -enc ...",
        raw={"_time": "2026-06-12", "host": "WS-001", "src_ip": "10.1.2.3"},
    )
    base.update(overrides)
    return SigmaHit(**base)


def test_conversion_maps_all_fields():
    req = prs.sigma_hit_to_finding_request(_hit())
    assert req.source == HuntSource.HUNT_PACK
    assert req.domain == HuntDomain.SIGMA
    assert req.severity == Severity.HIGH
    assert req.technique_ids == ["T1059.001"]
    assert req.entities[0].kind == "host"
    assert req.entities[0].value == "WS-001"
    assert req.observables[0].type == "ip"
    assert req.observables[0].value == "10.1.2.3"
    # title carries rule + primary entity so duplicate rules read distinctly
    assert "Encoded PowerShell" in req.title
    assert "WS-001" in req.title
    # evidence carries the provenance needed to pivot back to the detection
    ev = req.evidence
    assert ev["pack_id"] == "hpack_abc"
    assert ev["rule_id"] == "rule_1"
    assert ev["rule_title"] == "Encoded PowerShell"
    assert ev["backend"] == "splunk"
    assert ev["source_run_id"] == "hrun_test"
    assert ev["raw"]["host"] == "WS-001"


def test_conversion_drops_observable_without_type():
    req = prs.sigma_hit_to_finding_request(_hit(observable="x", observable_type=None))
    assert req.observables == []


def test_conversion_title_falls_back_to_observable_then_rule():
    req = prs.sigma_hit_to_finding_request(
        _hit(entities=[], observable="evil.com", observable_type="domain")
    )
    assert "evil.com" in req.title
    bare = prs.sigma_hit_to_finding_request(
        _hit(entities=[], observable=None, observable_type=None)
    )
    assert bare.title == "Encoded PowerShell"


def test_raw_evidence_truncated_when_oversized():
    big = {"blob": "x" * 10_000}
    req = prs.sigma_hit_to_finding_request(_hit(raw=big))
    raw = req.evidence["raw"]
    assert raw["_truncated"] is True
    assert "_preview" in raw
    assert len(json.dumps(raw)) < 10_000


def test_raw_evidence_kept_whole_when_small():
    req = prs.sigma_hit_to_finding_request(_hit(raw={"host": "WS-001"}))
    assert req.evidence["raw"] == {"host": "WS-001"}


def test_dedupe_collapses_identical_hits_within_batch():
    hits = [_hit(), _hit(), _hit()]  # same rule + host + observable
    reqs = prs.hits_to_finding_requests(hits)
    assert len(reqs) == 1


def test_dedupe_keeps_distinct_entities():
    hits = [
        _hit(entities=[SigmaHitEntity(kind="host", value="WS-001")]),
        _hit(entities=[SigmaHitEntity(kind="host", value="WS-002")]),
    ]
    reqs = prs.hits_to_finding_requests(hits)
    assert len(reqs) == 2


def test_dedupe_keeps_distinct_backends():
    reqs = prs.hits_to_finding_requests([_hit(backend="splunk"), _hit(backend="sentinel")])
    assert len(reqs) == 2


# --------------------------------------------------------------------------- #
# Scheduled-run service end-to-end (engine mock connectors)
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _mock_connectors(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    # get_settings is lru_cached — clear so the env flip takes effect.
    from btagent_backend.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_run_pack_and_ingest_lands_findings_and_history(db_session):
    run_rows = await prs.run_pack_and_ingest(
        db_session,
        org_id=DEFAULT_ORG_ID,
        backends=["splunk"],
        max_hits_per_query=5,
        emit_events=False,
    )
    assert len(run_rows) == 1
    run = run_rows[0]
    assert run.status == "completed"
    assert run.hit_count >= run.findings_created  # dedupe collapses duplicates
    assert run.findings_created >= 1
    # rule_stats carries a per-rule rollup
    assert run.rule_stats
    assert all({"title", "hits", "errors"} <= set(v) for v in run.rule_stats.values())

    # findings actually landed in the inbox, sourced from this run's pack.
    # The in-memory inbox is shared across tests, so scope to this run's id.
    from sqlalchemy import select

    from btagent_backend.db.models_hunt import HuntFindingRow

    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(HuntFindingRow.org_id == DEFAULT_ORG_ID)
            )
        )
        .scalars()
        .all()
    )
    mine = [r for r in rows if (r.evidence or {}).get("source_run_id") == run.run_id]
    assert len(mine) == run.findings_created
    assert all(r.source == HuntSource.HUNT_PACK.value for r in mine)


async def test_run_pack_respects_active_suppression(db_session):
    # First run to learn what a real finding looks like, then suppress that
    # rule's pattern and confirm a second run's matching hits are suppressed.
    run_rows = await prs.run_pack_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, backends=["splunk"], emit_events=False
    )
    _, findings, _, _ = await svc.list_clusters(
        db_session, org_id=DEFAULT_ORG_ID, include_suppressed=True
    )
    assert findings
    with_tech = [f for f in findings if f.technique_ids]
    assert with_tech, "expected at least one pack finding carrying a technique"
    techniques = with_tech[0].technique_ids
    # Suppress by technique set (a realistic, non-overbroad criterion).
    await svc.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="known pack noise",
        reason="baseline hunt noise, approved",
        match=SuppressionMatch(source=HuntSource.HUNT_PACK, technique_ids=techniques),
        created_by=None,
    )

    before = await _count_suppressed(db_session)
    await prs.run_pack_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, backends=["splunk"], emit_events=False
    )
    after = await _count_suppressed(db_session)
    assert after > before  # the matching second-run hits were suppressed pre-insert


async def _count_suppressed(db) -> int:
    _, findings, _, _ = await svc.list_clusters(db, org_id=DEFAULT_ORG_ID, include_suppressed=True)
    return sum(1 for f in findings if f.state == "suppressed")


# --------------------------------------------------------------------------- #
# Suppression sweep audit (#119 Phase C)
# --------------------------------------------------------------------------- #


async def _add_rule(db, *, expires_at=None, reconfirm_at=None):
    rule = SuppressionRuleRow(
        id=generate_id("supp"),
        org_id=DEFAULT_ORG_ID,
        name="r",
        reason="because",
        match={"source": "hunt_pack"},
        state="active",
        expires_at=expires_at,
        reconfirm_at=reconfirm_at,
        created_at=datetime.now(UTC),
    )
    db.add(rule)
    await db.flush()
    return rule


async def test_sweep_audits_expiry(db_session):
    now = datetime.now(UTC)
    await _add_rule(db_session, expires_at=now - timedelta(hours=1))
    from btagent_backend.services.audit_trail import AuditTrail

    audit = AuditTrail(db_session)
    before = len(await audit.get_entries(category=AuditCategory.HUNT, limit=100))

    counts = await svc.sweep_stale_suppressions(db_session, now=now)
    assert counts["expired"] == 1

    entries = await audit.get_entries(category=AuditCategory.HUNT, limit=100)
    assert len(entries) == before + 1
    assert entries[0].action == "suppression_expired"
    assert entries[0].actor == "system:suppression_sweep"


async def test_sweep_audits_reconfirm_and_leaves_fresh(db_session):
    now = datetime.now(UTC)
    await _add_rule(db_session, reconfirm_at=now - timedelta(hours=1))
    fresh = await _add_rule(
        db_session, reconfirm_at=now + timedelta(days=30), expires_at=now + timedelta(days=60)
    )

    counts = await svc.sweep_stale_suppressions(db_session, now=now)
    assert counts["needs_reconfirm"] == 1

    from btagent_backend.services.audit_trail import AuditTrail

    entries = await AuditTrail(db_session).get_entries(category=AuditCategory.HUNT, limit=100)
    assert any(e.action == "suppression_needs_reconfirm" for e in entries)
    await db_session.refresh(fresh)
    assert fresh.state == "active"  # untouched


# --------------------------------------------------------------------------- #
# Pack-runs API (RBAC + org-scope + pagination)
# --------------------------------------------------------------------------- #


async def _seed_run(db, *, org_id=DEFAULT_ORG_ID, **overrides):
    now = datetime.now(UTC)
    row = HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=generate_id("hrun"),
        pack_id="hpack_abc",
        pack_name="Windows Baseline",
        pack_version="1.0.0",
        backends=["splunk"],
        rule_stats={"rule_1": {"title": "t", "hits": 2, "errors": 0}},
        hit_count=2,
        error_count=0,
        findings_created=1,
        status="completed",
        started_at=now,
        completed_at=now,
    )
    for k, v in overrides.items():
        setattr(row, k, v)
    db.add(row)
    await db.commit()
    return row


async def test_pack_runs_requires_auth(client):
    resp = await client.get("/api/v1/hunt/pack-runs")
    assert resp.status_code in (401, 403)


async def test_pack_runs_lists_org_scoped(client, analyst_token, db_session):
    await _seed_run(db_session)
    resp = await client.get("/api/v1/hunt/pack-runs", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total"] >= 1
    assert all(item["org_id"] == DEFAULT_ORG_ID for item in data["items"])
    assert data["items"][0]["rule_stats"]


async def test_pack_runs_excludes_other_orgs(client, analyst_token, db_session):
    # A run for a different org must not show in the caller's list.
    from btagent_backend.db.models import OrganizationRow

    other = OrganizationRow(id=generate_id("org"), name="Other", created_at=datetime.now(UTC))
    db_session.add(other)
    await db_session.commit()
    await _seed_run(db_session, org_id=other.id)

    resp = await client.get("/api/v1/hunt/pack-runs", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    assert all(item["org_id"] == DEFAULT_ORG_ID for item in resp.json()["items"])


async def test_pack_runs_paginates(client, analyst_token, db_session):
    for _ in range(3):
        await _seed_run(db_session)
    resp = await client.get(
        "/api/v1/hunt/pack-runs?page=1&page_size=2", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["items"]) == 2
