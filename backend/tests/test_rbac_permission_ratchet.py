"""Every permission a route requires is declared, and every declared one is used.

``has_permission`` resolves an unknown permission to ``False`` — for **every**
role, admin included:

    required_role = PERMISSIONS.get(permission)
    if required_role is None:
        return False

So a route requiring a permission the registry does not declare — a typo, a
rename, a permission removed while its call site stayed — is not callable by
anybody, and the failure surfaces as a 403. A 403 from an RBAC gate is exactly
what correct enforcement looks like, so nothing about the symptom says the
route is unreachable rather than merely restricted. That is the same shape as
#596/#598: a capability that exists, is enforced, and has no way in.

The other direction is milder but not nothing. Eight permissions are declared
and required nowhere, so the role matrix advertises capabilities the API does
not expose — ``investigation:delete`` and ``user:delete`` name operations with
no route at all, and ``containment:approve`` names a step that is a request
field rather than an endpoint. An auditor reading the matrix would conclude
those are restricted capabilities; they are absent ones. Listing them keeps
that honest and makes a new orphan a visible decision.

Scope, stated rather than implied: this proves each required permission is
*declared*, not that the role it maps to is the right one. Whether
``containment:execute`` should sit at incident_commander rather than
senior_analyst is a policy question no static check can settle.
"""

from __future__ import annotations

import re
from pathlib import Path

from btagent_shared.types.enums import UserRole

from btagent_backend.auth.rbac import PERMISSIONS, has_permission

_CALL = re.compile(r'require_permission\(\s*["\']([^"\']+)["\']')

#: Declared permissions that no call site requires, and why each is kept.
#:
#: These are not oversights to delete on sight — several name a real intent
#: whose route does not exist yet. The value has to say which, so a future
#: reader can tell "reserved" from "left behind".
_UNUSED_PERMISSIONS: dict[str, str] = {
    "containment:approve": (
        "Approval is a request field (``approved``) on the execute routes, not "
        "its own endpoint — the double-gate is RBAC + that flag. Reserved for "
        "a separate approve endpoint."
    ),
    "containment:propose": (
        "Proposals are created by the agent, not by an analyst calling a route. "
        "Reserved for an analyst-authored proposal endpoint."
    ),
    "hitl:reject": (
        "The HITL resume path takes an approve/reject decision on one route "
        "gated by the approve permission; reject has no separate endpoint."
    ),
    "investigation:delete": "No delete endpoint exists — investigations are archived, not deleted.",
    "playbook:execute_containment": (
        "Playbook containment steps route through the containment execute "
        "path, which applies its own ``containment:execute`` gate."
    ),
    "user:delete": "No user-delete endpoint exists; deactivation is the supported path.",
    "user:view": "User listing is served by the org/admin surfaces under their own gates.",
    "webhook:manage": "No webhook endpoints exist yet.",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _required_permissions() -> dict[str, list[str]]:
    """{permission: [file:line, ...]} for every ``require_permission`` call."""
    found: dict[str, list[str]] = {}
    for path in (_repo_root() / "backend/btagent_backend").rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in _CALL.finditer(line):
                found.setdefault(match.group(1), []).append(f"{path.name}:{lineno}")
    return found


def test_the_scanner_finds_the_call_sites():
    """Guard the guard: an empty scan satisfies every assertion below.

    Both directions compare derived sets, so a regex that stopped matching —
    ``require_permission`` renamed, or called with a variable — would produce
    an empty mapping and still pass a subset check.
    """
    required = _required_permissions()
    assert len(required) >= 50, f"scanner found only {len(required)} permissions; it has broken"
    assert "investigation:view" in required, "a permission known to gate routes was not found"


def test_every_required_permission_is_declared():
    """An undeclared permission makes its route uncallable by everyone."""
    required = _required_permissions()
    undeclared = {p: sites for p, sites in required.items() if p not in PERMISSIONS}
    assert not undeclared, (
        "require_permission names a permission the RBAC registry does not declare, "
        "so the route 403s for every role including admin: "
        f"{ {p: s for p, s in undeclared.items()} }"
    )


def test_an_undeclared_permission_really_does_lock_everyone_out():
    """The premise, asserted rather than assumed.

    If ``has_permission`` ever started defaulting an unknown permission to
    *allowed*, the test above would be guarding against the wrong hazard — and
    the new hazard would be far worse. Pinning the behaviour makes that change
    a conversation.
    """
    assert has_permission(UserRole.ADMIN, "definitely:not-a-real-permission") is False
    assert has_permission(UserRole.ADMIN, "investigation:view") is True


def test_every_declared_permission_is_used_or_listed():
    """A permission that gates nothing advertises a capability that isn't there."""
    required = set(_required_permissions())
    orphans = set(PERMISSIONS) - required - set(_UNUSED_PERMISSIONS)
    assert not orphans, (
        f"declared permissions that gate nothing and are unlisted: {sorted(orphans)}. "
        "Require them at the route they were added for, or list them in "
        "_UNUSED_PERMISSIONS with the reason they are kept."
    )


def test_no_entry_outlives_its_reason():
    """The list only shrinks: an entry now in use must be delisted."""
    required = set(_required_permissions())
    stale = sorted(set(_UNUSED_PERMISSIONS) & required)
    assert not stale, (
        f"_UNUSED_PERMISSIONS entries are now required at a route: {stale}. Delete them."
    )


def test_listed_permissions_are_actually_declared():
    """A list entry for a permission the registry dropped is dead text."""
    ghosts = sorted(set(_UNUSED_PERMISSIONS) - set(PERMISSIONS))
    assert not ghosts, f"_UNUSED_PERMISSIONS names permissions no longer in the registry: {ghosts}"


def test_the_used_majority_is_actually_the_majority():
    """If most of the registry gates nothing, the matrix is fiction.

    A guard whose exemption list grows to cover the population records a norm
    nobody follows. Making that a failure keeps the list from becoming the
    place unused permissions go to be forgotten.
    """
    required = set(_required_permissions())
    used = len(set(PERMISSIONS) & required)
    assert used > len(PERMISSIONS) / 2, (
        f"only {used}/{len(PERMISSIONS)} declared permissions gate anything"
    )
