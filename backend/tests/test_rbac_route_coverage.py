"""Every v1 route enforces RBAC, or is exempt on the record.

``user.require_permission(...)`` is the authorization control for the whole
HTTP surface — 228 routes and counting. Forgetting it on a new route is not a
loud failure: the endpoint works, tests pass, and any authenticated principal
can call it regardless of role. That is the shape of an authorization hole,
and nothing in the suite noticed one until this file.

The rule: a route function either enforces a permission (directly, or through
a helper in its own module that does), or appears in :data:`NO_PERMISSION_CHECK`
with the reason it legitimately cannot.

Following helpers matters and is not incidental. ``cti_detection``'s accept and
reject routes both delegate to a shared ``_review`` shell that calls
``require_permission("hunt:triage")`` — a naive per-function scan reports them
as unguarded, and "fixing" that by exempting them would record a falsehood in
the one place people trust.

Static, not runtime: this asks what the source says, so a route added without
a check fails here at PR time rather than in whatever environment first calls
it with the wrong role.
"""

from __future__ import annotations

import ast
from pathlib import Path

_API_V1 = Path(__file__).resolve().parent.parent / "btagent_backend" / "api" / "v1"

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})


# Routes with no ``require_permission``, and why that is correct. Grouped by
# the *kind* of reason, because "self-scoped" and "pre-auth" fail in different
# ways if someone gets them wrong.
NO_PERMISSION_CHECK: dict[str, str] = {
    # --- Pre-auth: there is no principal yet to check a permission against. ---
    "auth.py::login": "pre-auth: establishes the session",
    "auth.py::refresh": "pre-auth: rotates on refresh-token possession, not role",
    "auth.py::logout": "pre-auth-adjacent: revokes the caller's own session",
    "auth.py::me": "self-scoped: returns the caller's own principal",
    "health.py::health": "unauthenticated liveness probe (by design)",
    "health.py::readiness": "unauthenticated readiness probe (by design)",
    "saml.py::saml_login": "pre-auth: IdP redirect target",
    "saml.py::saml_acs": "pre-auth: IdP assertion consumer",
    "saml.py::saml_metadata": "pre-auth: static SP metadata document",
    "sso.py::sso_login": "pre-auth: OIDC redirect target",
    "sso.py::sso_callback": "pre-auth: OIDC callback",
    # --- Separately authenticated: a different credential, not a user role. ---
    # webhooks._verify_secret authenticates against the dedicated
    # BTAGENT_WEBHOOK_SECRET and DENIES when it is unset (SEC #372) — these
    # callers are SIEM/EDR alert actions, which hold no user identity.
    "webhooks.py::ingest_splunk": "HMAC webhook secret, not a user principal",
    "webhooks.py::ingest_crowdstrike": "HMAC webhook secret, not a user principal",
    "webhooks.py::ingest_sentinel": "HMAC webhook secret, not a user principal",
    "webhooks.py::ingest_elastic": "HMAC webhook secret, not a user principal",
    # --- Self-scoped: the query is keyed on the caller's own id, so there is
    # --- no cross-principal read or write for a permission to gate.
    "config.py::get_dashboard_layout": "self-scoped: DashboardPrefRow keyed on user.id",
    "config.py::put_dashboard_layout": "self-scoped: writes the caller's own layout",
    "config.py::reset_dashboard_layout": "self-scoped: clears the caller's own layout",
    "mfa.py::mfa_status": "self-scoped: UserMFARow keyed on current_user.id",
    "mfa.py::enroll": "self-scoped: enrols the caller's own factor",
    "mfa.py::confirm": "self-scoped: confirms the caller's own factor",
    "mfa.py::disable": "self-scoped: disables the caller's own factor",
    "mfa.py::verify": "self-scoped: verifies the caller's own factor",
    "notifications.py::get_preferences": "self-scoped: NotificationPrefRow keyed on user.id",
    "notifications.py::put_preferences": "self-scoped: writes the caller's own prefs",
    "notifications.py::list_notifications": "self-scoped: filtered on user_id == user.id",
    "notifications.py::mark_notification_read": "self-scoped: mark_read(..., user.id)",
    "notifications.py::mark_all_notifications_read": "self-scoped: mark_all_read(db, user.id)",
}


def _is_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if (
            isinstance(target, ast.Attribute)
            and target.attr in _HTTP_METHODS
            and isinstance(target.value, ast.Name)
            and "router" in target.value.id
        ):
            return True
    return False


def _called_names(node: ast.AST) -> set[str]:
    """Bare names this node calls — enough to spot local helper delegation."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            names.add(sub.func.id)
    return names


def _enforces_directly(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr == "require_permission":
                return True
    return False


def _routes_without_enforcement() -> dict[str, str]:
    """``{"module.py::func": ""}`` for routes with no reachable permission check."""
    unenforced: dict[str, str] = {}
    for path in sorted(_API_V1.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
        # Module-local helpers that themselves enforce — one hop is enough for
        # the delegation shape actually in use (route -> _review -> check).
        enforcing_helpers = {f.name for f in funcs if not _is_route(f) and _enforces_directly(f)}
        for func in funcs:
            if not _is_route(func):
                continue
            if _enforces_directly(func):
                continue
            if _called_names(func) & enforcing_helpers:
                continue
            unenforced[f"{path.name}::{func.name}"] = ""
    return unenforced


def _all_routes() -> list[str]:
    out: list[str] = []
    for path in sorted(_API_V1.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        out.extend(
            f"{path.name}::{n.name}"
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and _is_route(n)
        )
    return out


def test_extraction_actually_finds_routes():
    """Guard the guard: a broken matcher would wave everything through."""
    routes = _all_routes()
    assert len(routes) >= 200, f"only found {len(routes)} routes; matcher broken?"
    assert "investigations.py::create_investigation" in routes


def test_helper_delegation_is_followed():
    """The accept/reject pair enforces via ``_review`` — not by exemption.

    Pinned because a regression here is invisible in the good direction: the
    scan would start reporting genuinely-guarded routes as holes, and the
    natural "fix" is to exempt them, which writes a false claim into the map.
    """
    unenforced = _routes_without_enforcement()
    assert "cti_detection.py::accept_detection_proposal" not in unenforced
    assert "cti_detection.py::reject_detection_proposal" not in unenforced


def test_every_route_enforces_rbac_or_is_declared():
    undeclared = sorted(set(_routes_without_enforcement()) - set(NO_PERMISSION_CHECK))
    assert not undeclared, (
        "These routes never reach user.require_permission(...), so any "
        "authenticated principal can call them regardless of role:\n  "
        + "\n  ".join(undeclared)
        + "\n\nAdd the permission check, or — if the route is pre-auth, "
        "self-scoped to the caller's own id, or authenticated by a different "
        "credential — add it to NO_PERMISSION_CHECK with that reason."
    )


def test_declared_exemptions_still_exist():
    """A stale exemption is dead weight, and hides the next real one."""
    stale = sorted(set(NO_PERMISSION_CHECK) - set(_all_routes()))
    assert not stale, (
        "These are exempted but are no longer routes:\n  "
        + "\n  ".join(stale)
        + "\n\nDelete them — the list only shrinks."
    )


def test_exemptions_that_gained_a_check_are_removed():
    """If an exempt route grew a permission check, the exemption is a lie."""
    now_enforced = sorted(
        set(NO_PERMISSION_CHECK) - set(_routes_without_enforcement()) & set(_all_routes())
    )
    assert not now_enforced, (
        "These enforce a permission now, so their NO_PERMISSION_CHECK entry is "
        "stale:\n  " + "\n  ".join(now_enforced)
    )
