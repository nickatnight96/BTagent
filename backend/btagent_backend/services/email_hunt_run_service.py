"""Email-hunt run service — connectors → findings → triage inbox (email vertical, slice 4).

The backend side-effectful shell for the email-hunt vertical. It closes the
loop the earlier slices set up:

* slice 1 (#273) — the pure ``phishing_incidents_to_findings`` mapper;
* slice 2 (#274) — the pure ``run_email_hunt`` correlate→map composition;
* slice 3 (#275) — ``run_email_hunt_over_connectors``, the async gather over the
  email MCP connectors.

This service runs that gather+correlate+map end-to-end and **persists** the
resulting findings into the #119 hunt-findings store via
:func:`hunt_triage_service.persist_hunt_findings` — so email findings land in
the same Hunt Triage inbox (clustering, suppression, promotion) as pack-run and
identity findings. It mirrors :func:`hunt_pack_run_service.run_pack_and_ingest`:
the persistence helper never commits — the caller (an API route or arq job)
owns the commit.

Mock-first: the email connectors default to mock mode, so this is safe to run
in CI and returns the deterministic fixture-driven findings.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import hunt_triage_service

logger = logging.getLogger("btagent.services.email_hunt_run")


def _default_email_servers() -> list[Any]:
    """Construct the mock-first email connectors this hunt gathers from.

    Lazy import: the connector classes live in the agents package, pulled in
    only when an email hunt actually runs (mirrors ``run_pack_and_ingest``'s
    lazy engine import). The connectors are constructed with their own
    mock-first default (the fleet-wide ``BTAGENT_MOCK_CONNECTORS`` switch,
    default ``true``); a production deployment flips that env to route to live
    mode (guarded, not yet implemented) rather than silently returning
    fixtures.
    """
    from btagent_agents.mcp.servers.defender_o365_mcp import DefenderO365MCPServer
    from btagent_agents.mcp.servers.mimecast_mcp import MimecastMCPServer
    from btagent_agents.mcp.servers.proofpoint_mcp import ProofpointMCPServer

    return [
        DefenderO365MCPServer(),
        ProofpointMCPServer(),
        MimecastMCPServer(),
    ]


async def run_email_hunt_and_ingest(
    db: AsyncSession,
    *,
    org_id: str = DEFAULT_ORG_ID,
    start: str,
    end: str,
    servers: list[Any] | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """Run an email hunt over the connectors and land its findings in triage.

    Gathers message / click / quarantine telemetry over ``[start, end]``,
    correlates it into ranked phishing incidents, maps those into hunt
    findings, and persists them (clustered + suppression-checked on insert).
    Not committed — the caller commits once.

    Returns a summary: incidents seen, findings emitted vs. actually created
    (suppressions drop the delta), the active-incident headline, and the
    severity breakdown.
    """
    # Lazy import keeps the agents dependency off the hot import path.
    from btagent_agents.plugins.triage.email_hunt import run_email_hunt_over_connectors

    servers = servers if servers is not None else _default_email_servers()
    result = await run_email_hunt_over_connectors(servers, start=start, end=end, limit=limit)

    rows = await hunt_triage_service.persist_hunt_findings(
        db, org_id=org_id, findings=result.findings
    )

    summary = {
        "org_id": org_id,
        "window": {"start": start, "end": end},
        "total_incidents": result.total_incidents,
        "active_incident_count": result.active_incident_count,
        "findings_emitted": len(result.findings),
        "findings_created": len(rows),
        "counts_by_severity": result.counts_by_severity,
    }
    logger.info("email_hunt_and_ingest org=%s: %s", org_id, summary)
    return summary
