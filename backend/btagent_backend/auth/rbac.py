"""Role-based access control definitions."""

from btagent_shared.types.enums import UserRole

# Role hierarchy: higher roles inherit lower role permissions
ROLE_HIERARCHY: dict[UserRole, int] = {
    UserRole.ANALYST: 0,
    UserRole.SENIOR_ANALYST: 1,
    UserRole.INCIDENT_COMMANDER: 2,
    UserRole.ADMIN: 3,
}

# Permission map: action → minimum required role
PERMISSIONS: dict[str, UserRole] = {
    # Investigations
    "investigation:view": UserRole.ANALYST,
    "investigation:create": UserRole.ANALYST,
    "investigation:chat": UserRole.ANALYST,
    "investigation:pause": UserRole.ANALYST,
    "investigation:resume": UserRole.ANALYST,
    "investigation:stop": UserRole.SENIOR_ANALYST,
    "investigation:delete": UserRole.ADMIN,
    # HITL
    "hitl:approve": UserRole.SENIOR_ANALYST,
    "hitl:reject": UserRole.SENIOR_ANALYST,
    # Containment
    "containment:propose": UserRole.ANALYST,
    "containment:approve": UserRole.INCIDENT_COMMANDER,
    "containment:execute": UserRole.INCIDENT_COMMANDER,
    # Config
    "config:view": UserRole.ANALYST,
    "config:edit": UserRole.ADMIN,
    "config:org_profile": UserRole.ADMIN,
    # Users
    "user:view": UserRole.SENIOR_ANALYST,
    "user:create": UserRole.ADMIN,
    "user:edit": UserRole.ADMIN,
    "user:delete": UserRole.ADMIN,
    # Webhooks
    "webhook:manage": UserRole.ADMIN,
    # MITRE ATT&CK
    "mitre:view": UserRole.ANALYST,
    "mitre:tag": UserRole.SENIOR_ANALYST,
    "mitre:seed": UserRole.ADMIN,
    # IOCs
    "ioc:view": UserRole.ANALYST,
    "ioc:create": UserRole.ANALYST,
    "ioc:edit": UserRole.ANALYST,
    "ioc:delete": UserRole.SENIOR_ANALYST,
    "ioc:enrich": UserRole.ANALYST,
    "ioc:export": UserRole.ANALYST,
    # Knowledge base
    "knowledge:query": UserRole.ANALYST,
    "knowledge:ingest": UserRole.SENIOR_ANALYST,
    "knowledge:delete": UserRole.ADMIN,
    # Playbooks
    "playbook:view": UserRole.ANALYST,
    "playbook:create": UserRole.SENIOR_ANALYST,
    "playbook:edit": UserRole.SENIOR_ANALYST,
    # Symmetric with ``playbook:create`` / ``playbook:edit``: SOAR authors are
    # senior analysts who own the playbook lifecycle (the delete is soft-delete,
    # i.e. ``active=false``; full removal still requires admin via the DB).
    "playbook:delete": UserRole.SENIOR_ANALYST,
    "playbook:execute": UserRole.SENIOR_ANALYST,
    "playbook:execute_containment": UserRole.INCIDENT_COMMANDER,
    # Workflows (Phase 2 v1 — workflow CRUD store)
    # Analysts can browse/run workflows; senior_analyst authors and edits;
    # publishing a new version is the gate that pushes new automation to
    # the production-running pipeline so it's also senior; deprecate-
    # without-replacement is admin-only because it can take live
    # automation offline.
    "workflow:view": UserRole.ANALYST,
    "workflow:create": UserRole.SENIOR_ANALYST,
    "workflow:edit": UserRole.SENIOR_ANALYST,
    "workflow:publish": UserRole.SENIOR_ANALYST,
    "workflow:deprecate": UserRole.ADMIN,
    # Proactive threat hunting (Phase 6)
    # Analysts browse + triage the hunt inbox; suppressing noise and
    # promoting a finding into a full investigation are senior actions
    # because they shape what the SOC does (and doesn't) look at.
    "hunt:view": UserRole.ANALYST,
    "hunt:create": UserRole.ANALYST,
    "hunt:triage": UserRole.ANALYST,
    "hunt:suppress": UserRole.SENIOR_ANALYST,
    "hunt:promote": UserRole.SENIOR_ANALYST,
    # Hunt package + correlation workbench (UC-1.2 / UC-2.2): read-only
    # engine-backed pivots and advisory triage — analysts run these directly.
    "hunt:run": UserRole.ANALYST,
    # Alert triage (EPIC-3 UC-3.1): read-only auto-classification of an
    # alert into a reviewed case. Tier 1-2 analysts run it directly; the
    # node executes nothing, so this is a plain analyst capability.
    "triage:run": UserRole.ANALYST,
    # Response playbook (EPIC-3 UC-3.2): generate a dual-path containment plan
    # (proposal only — nothing executes). Parallel to ``containment:propose``:
    # proposing a plan is an analyst capability; approving/executing the
    # destructive steps is gated separately (``containment:approve`` /
    # ``containment:execute`` = incident_commander).
    "response:plan": UserRole.ANALYST,
    # Bulk IOC block & mitigation (EPIC-3 UC-3.3): generate a per-tool
    # block plan (proposal only — allowlist-screened, validated, every block
    # flagged for approval). Same posture as ``response:plan`` /
    # ``containment:propose``: planning is an analyst capability; approving and
    # executing the destructive blocks are gated separately.
    "mitigation:plan": UserRole.ANALYST,
    # Audit ledger (UC-7.1): read-only forensics surface over the SHA-256
    # hash-chain audit log. Senior analysts consume the ledger + lineage for
    # IR/forensics; CSV export for external auditors is admin-only.
    "audit:view": UserRole.SENIOR_ANALYST,
    "audit:export": UserRole.ADMIN,
    # TLP egress policy (#110 UC-7.2 — analysts see policy; CISO/admin writes).
    # Reading the exception set is senior_analyst+ so analysts know what may
    # leave the enclave; creating/revoking a policy widens egress and so
    # requires CISO sign-off (admin).
    "policy:view": UserRole.SENIOR_ANALYST,
    "policy:manage": UserRole.ADMIN,
    # Reports
    "report:view": UserRole.ANALYST,
    "report:generate": UserRole.ANALYST,
    "report:export": UserRole.ANALYST,
    "report:summarize": UserRole.SENIOR_ANALYST,
    # Remediation
    "remediation:generate": UserRole.ANALYST,
}


def has_permission(user_role: str, permission: str) -> bool:
    """Check if a role has a specific permission via hierarchy."""
    try:
        role = UserRole(user_role)
    except ValueError:
        return False

    required_role = PERMISSIONS.get(permission)
    if required_role is None:
        return False

    return ROLE_HIERARCHY.get(role, -1) >= ROLE_HIERARCHY.get(required_role, 999)
