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
    "playbook:delete": UserRole.ADMIN,
    "playbook:execute": UserRole.SENIOR_ANALYST,
    "playbook:execute_containment": UserRole.INCIDENT_COMMANDER,
    # Reports
    "report:view": UserRole.ANALYST,
    "report:generate": UserRole.ANALYST,
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
