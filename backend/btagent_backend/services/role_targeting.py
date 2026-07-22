"""Role-based notification targeting.

Shared resolver for "who in this org should hear about X": given an RBAC
permission string, returns the ids of every org user whose role meets that
permission's threshold (via the same ``PERMISSIONS`` / ``ROLE_HIERARCHY``
tables the API's ``require_permission`` uses, so a permission change
propagates to notification fan-outs without touching the producers).
"""

from __future__ import annotations

from collections.abc import Collection

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.rbac import PERMISSIONS, ROLE_HIERARCHY
from btagent_backend.db.models import UserRow


def roles_with_permission(permission: str) -> tuple[str, ...]:
    """Role values whose rank meets ``permission``'s minimum role."""
    required = PERMISSIONS[permission]
    threshold = ROLE_HIERARCHY[required]
    return tuple(role.value for role, rank in ROLE_HIERARCHY.items() if rank >= threshold)


async def user_ids_with_permission(
    db: AsyncSession,
    *,
    org_id: str,
    permission: str,
    exclude: Collection[str | None] = (),
) -> list[str]:
    """Ids of org users holding ``permission``, minus ``exclude`` entries."""
    result = await db.execute(
        select(UserRow.id).where(
            UserRow.org_id == org_id,
            UserRow.role.in_(roles_with_permission(permission)),
        )
    )
    excluded = {e for e in exclude if e}
    return [uid for (uid,) in result.all() if uid not in excluded]
