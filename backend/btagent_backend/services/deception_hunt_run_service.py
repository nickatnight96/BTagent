"""Deception-hunt run service — Canary → findings → triage inbox (deception vertical, slice 3).

The backend side-effectful shell for the deception-hunt vertical, mirroring
:mod:`email_hunt_run_service`. It runs the deception hunt over the Thinkst
Canary connector (slice 2's ``run_deception_hunt_over_connector``) and
**persists** the resulting findings into the #119 hunt-findings store via
:func:`hunt_triage_service.persist_hunt_findings` — so deception findings (the
fleet's highest-fidelity signal) land in the same Hunt Triage inbox as pack-run,
identity, and email findings.

Simpler than the email service: deception telemetry comes from a **single**
connector with no time window, so there's no window to compute. The
persistence helper never commits — the caller (an API route or arq job) owns
the commit. Mock-first: the Canary connector defaults to mock mode, so this is
safe to run in CI.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.deception_hunt_run")


def _default_deception_server() -> Any:
    """Construct the mock-first Thinkst Canary connector the hunt gathers from.

    Lazy import: the connector class lives in the agents package, pulled in only
    when a deception hunt actually runs. Constructed with its own mock-first
    default (the fleet-wide ``BTAGENT_MOCK_CONNECTORS`` switch); a production
    env flip routes to guarded live mode rather than silently returning
    fixtures.
    """
    from btagent_agents.mcp.servers.canary_mcp import CanaryMCPServer

    return CanaryMCPServer()


async def run_deception_hunt_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    server: Any | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Run a deception hunt over the Canary connector and land its findings.

    Gathers canary incidents, correlates them into ranked deception incidents,
    maps those into ``deception``-domain findings, and persists them (clustered
    + suppression-checked on insert). Not committed — the caller commits once.

    Returns a summary: incidents seen, active-intruder headline, findings
    emitted vs. actually created (suppressions drop the delta), and the
    severity breakdown.
    """
    from btagent_agents.plugins.triage.deception_hunt import run_deception_hunt_over_connector

    server = server if server is not None else _default_deception_server()
    result = await run_deception_hunt_over_connector(server, limit=limit)

    rows = await hunt_triage_service.persist_hunt_findings(
        db, org_id=org_id, findings=result.findings
    )

    summary = {
        "org_id": org_id,
        "total_incidents": result.total_incidents,
        "active_intruder_count": result.active_intruder_count,
        "findings_emitted": len(result.findings),
        "findings_created": len(rows),
        "counts_by_severity": result.counts_by_severity,
    }
    logger.info("deception_hunt_and_ingest org=%s: %s", org_id, summary)
    return summary
