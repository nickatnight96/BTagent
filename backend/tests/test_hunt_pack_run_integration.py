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


def test_dedupe_keeps_distinct_entity_kinds_same_value():
    """Codex #202 P2: host=alice and user=alice must NOT collide — the key
    includes each entity's (kind, value) pair, not just the value."""
    hits = [
        _hit(entities=[SigmaHitEntity(kind="host", value="alice")]),
        _hit(entities=[SigmaHitEntity(kind="user", value="alice")]),
    ]
    reqs = prs.hits_to_finding_requests(hits)
    assert len(reqs) == 2


def test_dedupe_keeps_distinct_observable_types_same_value():
    """Codex #202 P2: same observable string, different type stays distinct."""
    hits = [
        _hit(observable="x", observable_type="ip"),
        _hit(observable="x", observable_type="domain"),
    ]
    reqs = prs.hits_to_finding_requests(hits)
    assert len(reqs) == 2


# --------------------------------------------------------------------------- #
# Run status derivation (Codex #202 P2)
# --------------------------------------------------------------------------- #


def _result(*rule_specs) -> "engine_runner.PackRunResult":
    """Build a PackRunResult from ``(rule_id, [(backend, error_or_None), ...])``."""
    PackRunResult = engine_runner.PackRunResult
    RuleRunResult = engine_runner.RuleRunResult
    BackendRunResult = engine_runner.BackendRunResult
    now = datetime.now(UTC)
    rule_results = []
    for rule_id, backends in rule_specs:
        brs = [
            BackendRunResult(
                backend=b,
                query=None if err else "q",
                hit_count=0,
                hits=[],
                error=err,
            )
            for b, err in backends
        ]
        rule_results.append(RuleRunResult(rule_id=rule_id, rule_title=rule_id, backend_results=brs))
    return PackRunResult(
        run_id=generate_id("hrun"),
        pack_id="hpack_abc",
        pack_name="p",
        pack_version="1",
        backends=["splunk", "sentinel"],
        started_at=now,
        completed_at=now,
        rule_results=rule_results,
    )


def test_status_completed_when_no_errors():
    res = _result(("r1", [("splunk", None), ("sentinel", None)]))
    assert prs._derive_run_status(res) == "completed"


def test_status_failed_when_every_execution_errored():
    res = _result(
        ("r1", [("splunk", "boom")]),
        ("r2", [("sentinel", "kaboom")]),
    )
    assert prs._derive_run_status(res) == "failed"


def test_status_completed_with_errors_when_partial():
    res = _result(
        ("r1", [("splunk", None), ("sentinel", "boom")]),
    )
    assert prs._derive_run_status(res) == "completed_with_errors"


async def test_persist_pack_run_records_derived_status(db_session):
    res = _result(("r1", [("splunk", None), ("sentinel", "boom")]))
    row, _created = await prs.persist_pack_run(db_session, org_id=DEFAULT_ORG_ID, result=res)
    assert row.status == "completed_with_errors"


async def test_persist_pack_run_carries_truncation(db_session):
    """E7: a capped sweep must be distinguishable from a clean full one.

    The runner sets ``truncated`` + ``rules_not_run`` when the rules-per-sweep
    cap or the per-run deadline stops it early. A truncated run still lands
    ``completed``, so if these don't reach the row nothing downstream can tell
    "we looked everywhere and found nothing" from "we stopped looking".
    """
    res = _result(("r1", [("splunk", None)]))
    res.truncated = True
    res.rules_not_run = ["r2", "r3"]

    row, _created = await prs.persist_pack_run(db_session, org_id=DEFAULT_ORG_ID, result=res)

    assert row.truncated is True
    assert row.rules_not_run == ["r2", "r3"]
    # Status is unchanged by truncation — which is exactly why the flag exists.
    assert row.status == "completed"


async def test_persist_pack_run_defaults_to_not_truncated(db_session):
    res = _result(("r1", [("splunk", None)]))
    row, _created = await prs.persist_pack_run(db_session, org_id=DEFAULT_ORG_ID, result=res)
    assert row.truncated is False
    assert row.rules_not_run == []


# --------------------------------------------------------------------------- #
# Resume-from-checkpoint (#112 — "survives worker restart")
# --------------------------------------------------------------------------- #


def _hit_for(rule_id: str, run_id: str) -> "SigmaHit":
    """One hit for ``rule_id`` on splunk, correlated to ``run_id``."""
    return SigmaHit(
        source_run_id=run_id,
        pack_id="hpack_resume",
        rule_id=rule_id,
        rule_title=f"Rule {rule_id}",
        backend="splunk",
        severity=Severity.HIGH,
        mitre_techniques=["T1059"],
        entities=[SigmaHitEntity(kind="host", value=f"host-{rule_id}")],
        observable=None,
        observable_type=None,
        summary=f"hit for {rule_id}",
        raw={"host": f"host-{rule_id}"},
    )


def _result_with_hits(run_id: str, *rule_ids: str) -> "engine_runner.PackRunResult":
    """A PackRunResult where each rule fires exactly one splunk hit."""
    PackRunResult = engine_runner.PackRunResult
    RuleRunResult = engine_runner.RuleRunResult
    BackendRunResult = engine_runner.BackendRunResult
    now = datetime.now(UTC)
    rule_results = [
        RuleRunResult(
            rule_id=rid,
            rule_title=f"Rule {rid}",
            backend_results=[
                BackendRunResult(
                    backend="splunk", query="q", hit_count=1, hits=[_hit_for(rid, run_id)]
                )
            ],
        )
        for rid in rule_ids
    ]
    return PackRunResult(
        run_id=run_id,
        pack_id="hpack_resume",
        pack_name="Resume Pack",
        pack_version="1",
        backends=["splunk"],
        started_at=now,
        completed_at=now,
        rule_results=rule_results,
    )


async def _seed_org(db) -> str:
    """A dedicated org (SHARED-DB isolation rule) so exact counts don't drift."""
    from btagent_backend.db.models import OrganizationRow

    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name=f"Resume Org {org_id}", created_at=datetime.now(UTC)))
    await db.commit()
    return org_id


async def _run_row_by_run_id(db, run_id: str) -> "HuntPackRunRow":
    from sqlalchemy import select

    return (
        await db.execute(select(HuntPackRunRow).where(HuntPackRunRow.run_id == run_id))
    ).scalar_one()


async def test_hunt_pack_run_resume(db_session, monkeypatch):
    """A run interrupted after rule N resumes at rule N+1 (no re-ingest).

    Three-rule run; ``persist_hunt_findings`` is made to fail on its second
    call, so the run dies after rule 1 has been converted, ingested, and
    checkpointed. A fresh call with the same result + row (a "restarted
    worker") must skip rule 1 and land only rules 2 and 3.
    """
    org_id = await _seed_org(db_session)
    run_id = generate_id("hrun")
    result = _result_with_hits(run_id, "r1", "r2", "r3")

    real_persist = svc.persist_hunt_findings
    calls = {"n": 0}

    async def flaky_persist(db, *, org_id, findings):
        calls["n"] += 1
        if calls["n"] == 2:  # rule 1 lands; rule 2 dies mid-run
            raise RuntimeError("worker died mid-run")
        return await real_persist(db, org_id=org_id, findings=findings)

    monkeypatch.setattr(prs.hunt_triage_service, "persist_hunt_findings", flaky_persist)

    with pytest.raises(RuntimeError):
        await prs.persist_pack_run(db_session, org_id=org_id, result=result)

    # Checkpoint survived: a 'running' row naming exactly rule 1 as done.
    row = await _run_row_by_run_id(db_session, run_id)
    assert row.status == "running"
    assert row.progress["completed_rule_ids"] == ["r1"]
    assert row.findings_created == 1
    assert row.hit_count == 1

    # Restart: the fault is gone; resume the SAME run.
    monkeypatch.setattr(prs.hunt_triage_service, "persist_hunt_findings", real_persist)
    resumed, created = await prs.persist_pack_run(
        db_session, org_id=org_id, result=result, run_row=row
    )

    assert resumed.id == row.id  # the same history row, not a new one
    assert resumed.status == "completed"
    assert resumed.progress["completed_rule_ids"] == ["r1", "r2", "r3"]
    # Counters are cumulative; this call created only the two remaining rules.
    assert created == 2
    assert resumed.findings_created == 3
    assert resumed.hit_count == 3

    # Rule 1's finding was ingested once — the resume did not duplicate it.
    from sqlalchemy import select

    from btagent_backend.db.models_hunt import HuntFindingRow

    findings = (
        (await db_session.execute(select(HuntFindingRow).where(HuntFindingRow.org_id == org_id)))
        .scalars()
        .all()
    )
    mine = [f for f in findings if (f.evidence or {}).get("source_run_id") == run_id]
    rule_ids = sorted((f.evidence or {}).get("rule_id") for f in mine)
    assert rule_ids == ["r1", "r2", "r3"]  # exactly one finding per rule


async def test_run_pack_and_ingest_resumes_running_row(db_session, monkeypatch):
    """run_pack_and_ingest picks up an in-flight row and skips finished rules.

    Pre-seed a ``running`` row for the builtin pack with its first two rules
    already checkpointed; the resumed sweep must reuse that same row/run_id and
    only process the remaining rules, ending with every rule in the cursor.
    """
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    from btagent_backend.config import get_settings

    get_settings.cache_clear()

    from btagent_engine.hunting.pack import load_builtin_pack

    pack = load_builtin_pack("windows_baseline")
    enabled = [r.id for r in pack.enabled_rules]
    assert len(enabled) >= 3, "need a multi-rule pack to prove resume-at-N+1"
    already_done = enabled[:2]

    org_id = await _seed_org(db_session)
    seeded_run_id = generate_id("hrun")
    seeded = HuntPackRunRow(
        id=generate_id("hpkrun"),
        org_id=org_id,
        run_id=seeded_run_id,
        pack_id=pack.id,
        pack_name=pack.name,
        pack_version=pack.version,
        backends=["splunk"],
        rule_stats={rid: {"title": rid, "hits": 0, "errors": 0} for rid in already_done},
        hit_count=0,
        error_count=0,
        findings_created=0,
        status="running",
        progress={"completed_rule_ids": list(already_done)},
        started_at=datetime.now(UTC),
    )
    db_session.add(seeded)
    await db_session.commit()

    run_rows = await prs.run_pack_and_ingest(
        db_session,
        org_id=org_id,
        backends=["splunk"],
        max_hits_per_query=5,
        emit_events=False,
    )
    get_settings.cache_clear()

    assert len(run_rows) == 1
    run = run_rows[0]
    # Same logical run — resumed in place, not a fresh row.
    assert run.id == seeded.id
    assert run.run_id == seeded_run_id
    assert run.status in ("completed", "completed_with_errors")
    # Every enabled rule is now in the cursor; the first two were not re-run.
    assert set(run.progress["completed_rule_ids"]) == set(enabled)


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


async def test_pack_runs_exposes_truncation(client, analyst_token, db_session):
    """The coverage verdict has to survive all the way to the browser (E7)."""
    row = await _seed_run(db_session, truncated=True, rules_not_run=["r9", "r10"])

    resp = await client.get("/api/v1/hunt/pack-runs", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    item = next(i for i in resp.json()["items"] if i["id"] == row.id)
    assert item["truncated"] is True
    assert item["rules_not_run"] == ["r9", "r10"]


async def test_pack_runs_untruncated_run_reads_as_full_sweep(client, analyst_token, db_session):
    row = await _seed_run(db_session)
    resp = await client.get("/api/v1/hunt/pack-runs", headers=auth_header(analyst_token))
    item = next(i for i in resp.json()["items"] if i["id"] == row.id)
    assert item["truncated"] is False
    assert item["rules_not_run"] == []


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
