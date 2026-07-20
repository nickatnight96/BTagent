"""Agentic-misuse hunt run service — detectors → findings → triage inbox (#121).

The backend side-effectful shell for the agentic-misuse vertical, mirroring
:mod:`ndr_hunt_run_service`. It runs the agentic hunt (slice 1's
``run_agentic_hunt_mock``) and **persists** the resulting findings into the #119
hunt-findings store via :func:`hunt_triage_service.persist_hunt_findings` — so
agentic-misuse findings (prompt-injection, shadow agent/MCP, agent-identity
abuse) land in the same Hunt Triage inbox as pack-run, identity, email,
deception, and NDR findings.

Unlike the connector-backed verticals, the agentic domain has **no live
connector yet** (real-time LLM-call telemetry + agent-registration inventory are
deferred), so the hunt runs over the runner's deterministic demo bundle. The
persistence helper never commits — the caller (an API route) owns the commit.
Mock-first: the demo bundle is synthetic, so this is safe to run in CI.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.agentic_hunt_run")


async def run_agentic_hunt_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
) -> dict[str, Any]:
    """Run an agentic-misuse hunt and land its findings in the triage inbox.

    Runs the connector-independent detectors over the runner's demo bundle, maps
    their output into ``agentic``-domain findings, and persists them (clustered +
    suppression-checked on insert). Not committed — the caller commits once.

    Returns a summary: the observation-bundle size, findings emitted vs. actually
    created (suppressions drop the delta), and the severity breakdown.
    """
    from btagent_agents.plugins.triage.agentic_hunt import run_agentic_hunt_mock

    result = run_agentic_hunt_mock()

    rows = await hunt_triage_service.persist_hunt_findings(
        db, org_id=org_id, findings=result.findings
    )

    summary = {
        "org_id": org_id,
        "total_events": result.total_events,
        "total_identities": result.total_identities,
        "total_workloads": result.total_workloads,
        "findings_emitted": len(result.findings),
        "findings_created": len(rows),
        "counts_by_severity": result.counts_by_severity,
    }
    logger.info("agentic_hunt_and_ingest org=%s: %s", org_id, summary)
    return summary
