"""Shadow-agent governance workflow (#121/#117 Phase C).

Shadow-agent / shadow-MCP findings carry the ``evidence.shadow_workload=True``
routing marker (emitted identically by the cloud (#117) and agentic (#121)
detectors) and route to *governance*, not IR. This service records the
ruling in ``shadow_agent_registry``:

* ``register`` — the workload is sanctioned; bring it under management.
* ``sunset``  — the workload is to be decommissioned.

One row per (org, resource); re-governing updates the decision in place so
the registry always reflects the latest ruling. Never commits — the route
owns the transaction.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntFindingRow, ShadowAgentRegistryRow

logger = logging.getLogger("btagent.services.shadow_governance")

GOVERN_ACTIONS = {"register", "sunset"}
_STATUS_BY_ACTION = {"register": "registered", "sunset": "sunset"}


class NotAShadowFindingError(ValueError):
    """The finding lacks the shadow_workload governance routing marker."""


def _resource_key_from_finding(finding: HuntFindingRow) -> str:
    """Derive the stable governance key for the workload behind a finding.

    Preference order: cloud resource id observable → evidence identity_ref →
    first entity value → the finding id (last resort, still unique).
    """
    for obs in finding.observables or []:
        if obs.get("type") == "cloud_resource_id" and obs.get("value"):
            return str(obs["value"])
    identity_ref = (finding.evidence or {}).get("identity_ref")
    if identity_ref:
        return str(identity_ref)
    for entity in finding.entities or []:
        if entity.get("value"):
            return str(entity["value"])
    return finding.id


async def govern_finding(
    db: AsyncSession,
    *,
    org_id: str,
    finding_id: str,
    action: str,
    rationale: str,
    decided_by: str | None,
) -> ShadowAgentRegistryRow:
    """Record a register/sunset ruling for a shadow finding's workload.

    Raises :class:`ValueError` on an unknown action, ``LookupError`` when the
    finding is missing or cross-org, and :class:`NotAShadowFindingError` when
    the finding does not carry the governance routing marker.
    """
    if action not in GOVERN_ACTIONS:
        raise ValueError(f"Unknown governance action: {action!r}")

    finding = (
        await db.execute(
            select(HuntFindingRow).where(
                HuntFindingRow.id == finding_id, HuntFindingRow.org_id == org_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise LookupError(f"Hunt finding not found: {finding_id}")
    if not (finding.evidence or {}).get("shadow_workload"):
        raise NotAShadowFindingError(
            "Finding does not carry the shadow_workload governance marker; "
            "use the normal triage actions instead."
        )

    resource_key = _resource_key_from_finding(finding)
    kind = str((finding.evidence or {}).get("kind") or "unknown")
    status = _STATUS_BY_ACTION[action]
    now = datetime.now(UTC)

    existing = (
        await db.execute(
            select(ShadowAgentRegistryRow).where(
                ShadowAgentRegistryRow.org_id == org_id,
                ShadowAgentRegistryRow.resource_key == resource_key,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = ShadowAgentRegistryRow(
            id=generate_id("shreg"),
            org_id=org_id,
            resource_key=resource_key,
            kind=kind,
            status=status,
            decided_by=decided_by,
            rationale=rationale,
            source_finding_id=finding.id,
            created_at=now,
            updated_at=now,
        )
        db.add(existing)
    else:
        existing.status = status
        existing.decided_by = decided_by
        existing.rationale = rationale
        existing.source_finding_id = finding.id
        existing.kind = kind
        existing.updated_at = now

    await db.flush()
    logger.info(
        "shadow governance: %s %s (org=%s, finding=%s)",
        action,
        resource_key,
        org_id,
        finding.id,
    )
    return existing


async def list_registry(
    db: AsyncSession,
    *,
    org_id: str,
    status: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[ShadowAgentRegistryRow], int]:
    """Org-scoped registry, most recently decided first."""
    where = [ShadowAgentRegistryRow.org_id == org_id]
    if status:
        where.append(ShadowAgentRegistryRow.status == status)

    total = (
        await db.execute(select(func.count()).select_from(ShadowAgentRegistryRow).where(*where))
    ).scalar_one() or 0
    rows = (
        (
            await db.execute(
                select(ShadowAgentRegistryRow)
                .where(*where)
                .order_by(ShadowAgentRegistryRow.updated_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)
