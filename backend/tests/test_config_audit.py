"""Configuration-Center writes land on the audit ledger (#418).

Every mutating config endpoint (autonomy / feature-flags / org-profile /
retention) records a ``CONFIG_CHANGE`` entry so an admin's change is
defensible on the hash-chained ledger, not merely the application log. These
tests pin the autonomy and feature-flag PUT paths (both hit only the in-memory
SQLite schema, so no Postgres is required).
"""

import pytest_asyncio
from btagent_shared.types.enums import AuditCategory
from conftest import auth_header
from sqlalchemy import delete

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    AuditLogRow,
    FeatureFlagRow,
    OrgAutonomyRow,
)
from btagent_backend.services.audit_trail import AuditTrail


@pytest_asyncio.fixture(autouse=True)
async def _isolate(db_session):
    """Clear ledger + the config rows these writes touch, around each test.

    ``AuditTrail.record`` assigns ``seq = max+1`` while ``test_audit_trail.py``
    numbers from its own counter; leftover rows collide on the unique
    ``audit_logs.seq`` constraint. The autonomy/flag rows are cleared too so a
    stored override here can't leak into the autonomy-read tests (both live in
    the shared session-scoped ``DEFAULT_ORG_ID``).
    """
    for table in (AuditLogRow, FeatureFlagRow, OrgAutonomyRow):
        await db_session.execute(delete(table))
    await db_session.commit()
    yield
    for table in (AuditLogRow, FeatureFlagRow, OrgAutonomyRow):
        await db_session.execute(delete(table))
    await db_session.commit()


async def _config_entries(db_session, action: str):
    """CONFIG_CHANGE entries for the default org filtered to one action."""
    rows = await AuditTrail(db_session).get_entries(
        org_id=DEFAULT_ORG_ID, category=AuditCategory.CONFIG_CHANGE, limit=500
    )
    return [r for r in rows if r.action == action]


async def test_config_writes_are_audited(client, admin_token, db_session):
    # --- autonomy PUT ---------------------------------------------------- #
    resp = await client.put(
        "/api/v1/config/autonomy",
        headers=auth_header(admin_token),
        json={"overrides": {"siem_query": "L1"}},
    )
    assert resp.status_code == 200, resp.text

    autonomy_entries = await _config_entries(db_session, "config_autonomy_overrides_replaced")
    match = [e for e in autonomy_entries if e.details.get("overrides") == {"siem_query": "L1"}]
    assert match, "autonomy PUT did not write a CONFIG_CHANGE audit entry"
    entry = match[0]
    assert entry.category == AuditCategory.CONFIG_CHANGE.value
    assert entry.outcome == "success"
    assert entry.org_id == DEFAULT_ORG_ID
    assert entry.actor  # stamped with the acting admin's user id

    # --- feature-flag PUT ------------------------------------------------ #
    resp = await client.put(
        "/api/v1/config/feature-flags",
        headers=auth_header(admin_token),
        json={"flags": {"beta_search": True}},
    )
    assert resp.status_code == 200, resp.text

    flag_entries = await _config_entries(db_session, "config_feature_flags_replaced")
    flag_match = [e for e in flag_entries if e.details.get("flags") == {"beta_search": True}]
    assert flag_match, "feature-flag PUT did not write a CONFIG_CHANGE audit entry"
    assert flag_match[0].org_id == DEFAULT_ORG_ID
    assert flag_match[0].category == AuditCategory.CONFIG_CHANGE.value
