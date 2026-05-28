"""TLP egress policy CRUD + evaluation (EPIC-7 UC-7.2).

Persists org-scoped :class:`TLPPolicy` exceptions to the default-deny
egress gate and exposes an org-scoped evaluation entry point that loads
a tenant's policies and delegates the decision to the pure
``btagent_shared.security.tlp_policy.evaluate_egress_policy``.

All reads/writes are tenant-scoped by ``org_id`` — the caller passes the
authenticated user's org and never sees another tenant's policies.
"""

from __future__ import annotations

from datetime import datetime

from btagent_shared.security.tlp_policy import (
    PolicyDecision,
    TLPPolicy,
    TLPPolicyAction,
    evaluate_egress_policy,
)
from btagent_shared.types.config import TLP
from btagent_shared.utils.ids import generate_id
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import TLPPolicyRow


def _row_to_domain(row: TLPPolicyRow) -> TLPPolicy:
    """Convert a DB row into the pure shared TLPPolicy domain model."""
    return TLPPolicy(
        id=row.id,
        org_id=row.org_id,
        action=TLPPolicyAction(row.action),
        egress_kinds=tuple(row.egress_kinds or ()),
        applies_to_tlp=tuple(TLP(v) for v in (row.applies_to_tlp or ())),
        downgrade_to=TLP(row.downgrade_to) if row.downgrade_to else None,
        approver_id=row.approver_id or "",
        rationale=row.rationale or "",
        valid_until=row.valid_until,
        created_at=row.created_at,
    )


class TLPPolicyService:
    """CRUD + evaluation over the ``tlp_policies`` table."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_policies(self, org_id: str) -> list[TLPPolicy]:
        """All policies for an org, newest first."""
        result = await self._db.execute(
            select(TLPPolicyRow)
            .where(TLPPolicyRow.org_id == org_id)
            .order_by(TLPPolicyRow.created_at.desc())
        )
        return [_row_to_domain(r) for r in result.scalars().all()]

    async def get_policy(self, org_id: str, policy_id: str) -> TLPPolicy | None:
        row = await self._db.get(TLPPolicyRow, policy_id)
        if row is None or row.org_id != org_id:
            return None
        return _row_to_domain(row)

    async def create_policy(
        self,
        *,
        org_id: str,
        action: TLPPolicyAction,
        egress_kinds: list[str],
        applies_to_tlp: list[TLP],
        downgrade_to: TLP | None,
        approver_id: str,
        rationale: str,
        valid_until: datetime | None,
        created_by: str | None,
    ) -> TLPPolicy:
        row = TLPPolicyRow(
            id=generate_id("tpol"),
            org_id=org_id,
            action=action.value,
            egress_kinds=list(egress_kinds),
            applies_to_tlp=[t.value for t in applies_to_tlp],
            downgrade_to=downgrade_to.value if downgrade_to else None,
            approver_id=approver_id,
            rationale=rationale,
            valid_until=valid_until,
            created_by=created_by,
        )
        self._db.add(row)
        await self._db.flush()
        await self._db.refresh(row)
        return _row_to_domain(row)

    async def delete_policy(self, org_id: str, policy_id: str) -> bool:
        """Revoke (hard-delete) a policy. Returns False if not found in-org."""
        row = await self._db.get(TLPPolicyRow, policy_id)
        if row is None or row.org_id != org_id:
            return False
        await self._db.execute(
            delete(TLPPolicyRow).where(TLPPolicyRow.id == policy_id)
        )
        await self._db.flush()
        return True

    async def evaluate(
        self,
        *,
        org_id: str,
        tlp: TLP,
        egress_kind: str,
        now: datetime | None = None,
    ) -> PolicyDecision:
        """Decide an egress for an org by loading its policies and applying them.

        Default-deny is preserved by the shared evaluator: with no matching
        policy, TLP:RED is refused and anything below RED is allowed.
        """
        policies = await self.list_policies(org_id)
        return evaluate_egress_policy(
            tlp=tlp, egress_kind=egress_kind, policies=policies, now=now
        )


__all__ = ["TLPPolicyService"]
