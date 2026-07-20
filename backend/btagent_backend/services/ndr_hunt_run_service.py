"""NDR-hunt run service — Vectra → findings → triage inbox (NDR vertical, slice 3).

The backend side-effectful shell for the NDR-hunt vertical, mirroring
:mod:`deception_hunt_run_service`. It runs the NDR hunt over the Vectra AI
connector (slice 2's ``run_ndr_hunt_over_connector``) and **persists** the
resulting findings into the #119 hunt-findings store via
:func:`hunt_triage_service.persist_hunt_findings` — so NDR findings (per-host
kill-chain campaign rollups) land in the same Hunt Triage inbox as pack-run,
identity, email, and deception findings.

Like the deception service: NDR telemetry comes from a **single** connector with
no time window, so there's no window to compute. The persistence helper never
commits — the caller (an API route or arq job) owns the commit. Mock-first: the
Vectra connector defaults to mock mode, so this is safe to run in CI.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.ndr_hunt_run")


def _default_ndr_server() -> Any:
    """Construct the mock-first Vectra AI connector the hunt gathers from.

    Lazy import: the connector class lives in the agents package, pulled in only
    when an NDR hunt actually runs. Constructed with its own mock-first default
    (the fleet-wide ``BTAGENT_MOCK_CONNECTORS`` switch); a production env flip
    routes to guarded live mode rather than silently returning fixtures.
    """
    from btagent_agents.mcp.servers.vectra_mcp import VectraMCPServer

    return VectraMCPServer()


async def run_ndr_hunt_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    server: Any | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Run an NDR hunt over the Vectra connector and land its findings.

    Gathers Vectra detections, correlates them into ranked per-host campaign
    rollups, maps those into ``ndr``-domain findings, and persists them
    (clustered + suppression-checked on insert). Not committed — the caller
    commits once.

    Returns a summary: hosts seen, campaign headline, findings emitted vs.
    actually created (suppressions drop the delta), and the severity breakdown.
    """
    from btagent_agents.plugins.triage.ndr_hunt import run_ndr_hunt_over_connector

    server = server if server is not None else _default_ndr_server()
    result = await run_ndr_hunt_over_connector(server, limit=limit)

    rows = await hunt_triage_service.persist_hunt_findings(
        db, org_id=org_id, findings=result.findings
    )

    summary = {
        "org_id": org_id,
        "total_hosts": result.total_hosts,
        "campaign_count": result.campaign_count,
        "findings_emitted": len(result.findings),
        "findings_created": len(rows),
        "counts_by_severity": result.counts_by_severity,
    }
    logger.info("ndr_hunt_and_ingest org=%s: %s", org_id, summary)
    return summary
