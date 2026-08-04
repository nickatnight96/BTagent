"""Tenant scoping is a property of every route, not a habit of the last author.

The repo already has an RBAC route ratchet — it proves *who* may call an
endpoint. This one proves *whose rows come back*, which is a different
question: a route can be perfectly RBAC-correct and still hand an analyst
another organization's data.

Three scoping patterns are accepted, because the codebase legitimately uses
all three:

1. **Query filter** — ``.where(X.org_id == user.org_id)``. The common case.
2. **Fetch-then-assert** — load the row, then
   :func:`assert_can_access_investigation`, which 404s on cross-org (404 and
   not 403, so the response does not confirm the id exists).
3. **Inline compare** — an explicit ``row.org_id != user.org_id`` check, used
   where the row is not an investigation (e.g. ``POST /auth/revoke/{user_id}``
   comparing the target user's org).

A route handler that touches an org-scoped model and does none of the three
fails here. ``ROUTES_WITHOUT_TENANT_SCOPE`` is a ratchet: entries may be
removed, never added, and each needs a reason that survives someone asking
"so can org A read org B's rows through this?". It ships with the only two
routes for which the question does not apply — both pre-date having an
authenticated org to scope *by*.

Scope note, said plainly: this checks handlers that build their own query.
A handler that delegates to a service is only as scoped as the argument it
passes down — that is a semantic property this cannot see, and the
``_require_tenant_scope`` guard in ``ioc_service`` exists because of exactly
that gap. The second half of this file pins that guard.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[1] / "btagent_backend"
_API_V1 = _BACKEND / "api" / "v1"
_DB = _BACKEND / "db"
_SERVICES = _BACKEND / "services"

_HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
_QUERY_BUILDERS = {"select", "delete", "update"}

# Route handlers that query an org-scoped model and use none of the three
# recognized scoping patterns. Ratchet: entries come off, never on.
ROUTES_WITHOUT_TENANT_SCOPE: dict[str, str] = {
    "auth.py::login": (
        "Unauthenticated by definition — there is no caller org to scope by yet; "
        "the org comes *out* of this lookup and into the minted token. "
        "`UserRow.username` is `unique=True` globally, so the query matches at "
        "most one row, and authenticating as that user is the whole point."
    ),
    "auth.py::register": (
        "The pre-insert duplicate check must be global because the uniqueness "
        "constraint it mirrors is global (`username`/`email` are `unique=True`). "
        "Narrowing it to the admin's org would turn a clean 409 into a 500 from "
        "the DB constraint on a cross-org collision. The row it creates is "
        "scoped: `org_id=current_user.org_id`, never from the request body."
    ),
}


def _org_scoped_models() -> set[str]:
    """ORM classes carrying an ``org_id`` column — i.e. tenant-owned rows."""
    models: set[str] = set()
    for path in _DB.glob("models*.py"):
        src = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^class (\w+)\(([^)]*)\):(.*?)(?=^class |\Z)", src, re.S | re.M):
            if "org_id" in match.group(3):
                models.add(match.group(1))
    return models


def _is_route_handler(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr in _HTTP_METHODS
        for d in node.decorator_list
    )


def _models_queried(node: ast.AST, org_models: set[str]) -> set[str]:
    """Org-scoped models this function passes to select()/delete()/update()."""
    found: set[str] = set()
    for child in ast.walk(node):
        if not (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id in _QUERY_BUILDERS
        ):
            continue
        for arg in child.args:
            if isinstance(arg, ast.Name):
                name = arg.id
            elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                name = arg.value.id
            else:
                continue
            if name in org_models:
                found.add(name)
    return found


def _scoping_pattern(body: str) -> str | None:
    """Which of the three accepted patterns this handler uses, if any."""
    if ".org_id ==" in body or ".org_id.in_" in body:
        return "query-filter"
    if "assert_can_access_investigation" in body:
        return "fetch-then-assert"
    if re.search(r"\.org_id\s*!=", body):
        return "inline-compare"
    return None


def _audit() -> tuple[list[str], list[str]]:
    """Return (unscoped handler keys, scoped handler keys)."""
    org_models = _org_scoped_models()
    unscoped: list[str] = []
    scoped: list[str] = []
    for path in sorted(_API_V1.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not _is_route_handler(node):
                continue
            if not _models_queried(node, org_models):
                continue
            key = f"{path.name}::{node.name}"
            if _scoping_pattern(ast.unparse(node)) is None:
                unscoped.append(key)
            else:
                scoped.append(key)
    return unscoped, scoped


# ---------------------------------------------------------------------------
# The ratchet.
# ---------------------------------------------------------------------------


def test_every_route_touching_tenant_data_is_scoped():
    unscoped, _ = _audit()
    undeclared = sorted(set(unscoped) - set(ROUTES_WITHOUT_TENANT_SCOPE))
    assert not undeclared, (
        "route handler(s) query an org-scoped model with no tenant scoping:\n  "
        + "\n  ".join(undeclared)
        + "\n\nAdd one of: a `.where(X.org_id == user.org_id)` filter, an "
        "`assert_can_access_investigation(user, row)` call after loading the "
        "row, or an explicit `row.org_id != user.org_id` check. Declaring the "
        "route in ROUTES_WITHOUT_TENANT_SCOPE is a last resort and needs a "
        "reason that answers 'can org A read org B's rows through this?'."
    )


def test_declared_exemptions_are_still_real():
    """A stale exemption silently weakens the ratchet for a route that got fixed."""
    unscoped, _ = _audit()
    stale = sorted(set(ROUTES_WITHOUT_TENANT_SCOPE) - set(unscoped))
    assert not stale, f"exemption(s) no longer needed — delete them: {stale}"


# ---------------------------------------------------------------------------
# Guard the guard. A ratchet that inspects nothing passes forever.
# ---------------------------------------------------------------------------


def test_org_scoped_models_are_actually_found():
    models = _org_scoped_models()
    assert len(models) > 20, (
        f"only {len(models)} org-scoped models found; the model-parsing regex has "
        "probably drifted, which would make this whole file vacuous"
    )
    assert {"InvestigationRow", "IOCRow", "UserRow"} <= models


def test_the_audit_actually_inspects_route_handlers():
    _, scoped = _audit()
    assert len(scoped) > 10, (
        f"only {len(scoped)} scoped route handlers found; if route decorators or "
        "query construction were refactored, this file would pass by inspecting nothing"
    )


# ---------------------------------------------------------------------------
# The service-layer half: a tenant scope must not be optional.
# ---------------------------------------------------------------------------


def _functions_taking_investigation_id_in() -> list[tuple[str, ast.AST]]:
    out: list[tuple[str, ast.AST]] = []
    for path in sorted(_SERVICES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            names = [a.arg for a in node.args.kwonlyargs] + [a.arg for a in node.args.args]
            if "investigation_id_in" in names:
                out.append((f"{path.name}::{node.name}", node))
    return out


def test_the_scope_argument_scan_finds_something():
    assert _functions_taking_investigation_id_in(), (
        "no service function takes `investigation_id_in` — either the idiom was "
        "renamed (update this file) or the scan broke"
    )


@pytest.mark.parametrize(
    "key,node",
    _functions_taking_investigation_id_in(),
    ids=[k for k, _ in _functions_taking_investigation_id_in()],
)
def test_tenant_scope_is_not_optional(key: str, node: ast.AST):
    """A tenant filter must not be something a caller can forget.

    ``investigation_id_in`` used to default to ``None``, meaning "no filter".
    Every caller happened to pass it, so nothing was leaking — but the
    *default* was a full cross-tenant read, and omitting an argument is a
    thing people do. Each such function must now either declare the argument
    required, or call ``_require_tenant_scope`` to reject the no-scope case.
    """
    assert isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    kwonly = {a.arg: i for i, a in enumerate(node.args.kwonlyargs)}
    idx = kwonly.get("investigation_id_in")
    required = idx is not None and node.args.kw_defaults[idx] is None
    guarded = "_require_tenant_scope" in ast.unparse(node)
    assert required or guarded, (
        f"{key}: `investigation_id_in` is optional and the function does not call "
        "_require_tenant_scope, so calling it without a scope silently reads every "
        "organization's rows. Make the argument required, or add the guard."
    )
