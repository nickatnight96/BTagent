"""Every API route is reachable from the UI, or says why not.

Three consecutive slices found backend capability shipping with no consumer:
``POST /validation/emulate`` and ``GET /validation/coverage-map`` had no
frontend at all, and the TLP policy evaluator was never called on a real
egress. Each was found a release *after* it landed. Green CI said nothing,
because every layer was individually correct — the route worked, the service
worked, the tests passed. What was missing was the wiring, and nothing checks
for missing wiring.

This is the check. A route in ``api/v1`` must either:

* be called from ``frontend/src/api/*.ts``, or
* be listed in :data:`NOT_BROWSER_CALLED` — endpoints a browser genuinely
  never fetches (external webhook receivers, SAML/SSO redirect targets), or
* be listed in :data:`KNOWN_GAPS` — capability that really is unreachable
  today, named rather than hidden.

It is a **ratchet**, not a gate. The gap list is allowed to exist, but it may
only shrink:

* a NEW route with no consumer fails — the case worth catching, at PR time
  rather than three ticks later;
* a gap that has since been wired up but left in the list ALSO fails, so the
  list cannot quietly rot into a permanent exemption.

The distinction between the two lists matters and shouldn't be blurred:
``NOT_BROWSER_CALLED`` is "correct by design", ``KNOWN_GAPS`` is "debt with a
name". Moving something into the former to silence a failure is exactly the
mistake this file exists to prevent.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_API_DIR = _REPO / "backend" / "btagent_backend" / "api" / "v1"
_FRONTEND_SRC = _REPO / "frontend" / "src"

# --------------------------------------------------------------------------- #
# Declared exceptions
# --------------------------------------------------------------------------- #

# Endpoints no browser fetch will ever hit. Correct by design.
NOT_BROWSER_CALLED: dict[str, str] = {
    "POST /webhooks/splunk": "inbound push from Splunk; no browser caller",
    "POST /webhooks/crowdstrike": "inbound push from CrowdStrike; no browser caller",
    "POST /webhooks/sentinel": "inbound push from Microsoft Sentinel; no browser caller",
    "POST /webhooks/elastic": "inbound push from Elastic; no browser caller",
    "GET /auth/saml/{}/login": "full-page redirect to the IdP, not a fetch",
    "POST /auth/saml/{}/acs": "IdP posts the assertion here directly",
    "GET /auth/saml/{}/metadata": "SP metadata fetched by the IdP, not the SPA",
    "GET /auth/sso/{}/callback": "OIDC redirect target; the browser navigates, never fetches",
    "GET /health": "liveness probe for the orchestrator/load balancer",
    "GET /health/ready": "readiness probe for the orchestrator/load balancer",
}

# Capability that exists server-side and cannot be reached from the product.
# Each entry is debt. Delete the line when you wire it up — leaving it here
# after the fact fails this test on purpose.
KNOWN_GAPS: dict[str, str] = {
    "POST /mitre/seed": "matrix seeding is admin-only and run out of band, never from the UI",
    "POST /auth/refresh": "no SPA caller — sessions ride the cookie lifetime instead",
    "POST /memory": "agent-memory foundation (#482); frontend/UI explicitly deferred",
    "GET /memory": "agent-memory foundation (#482); frontend/UI explicitly deferred",
}


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

_ROUTER_PREFIX_RE = re.compile(r'APIRouter\((?:[^)]*?)prefix="([^"]+)"', re.S)
_ROUTE_RE = re.compile(r'@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"')
_PARAM_RE = re.compile(r"\{[^}]+\}")
_TS_PARAM_RE = re.compile(r"\$\{[^}]*\}")
# Any module-level ``const SOMETHING = "/v1/..."`` — clients name these BASE,
# IDENTITY_BASE, etc., so match on the value rather than the identifier.
_BASE_CONST_RE = re.compile(r'^const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(/[^"]*)"', re.M)
# Any ``/v1/...`` occurrence. Deliberately NOT anchored to a quote: clients
# build URLs as ``${BASE_URL}/v1/auth/login`` and ``/api/v1/audit/export``, so
# requiring a preceding quote loses them. The looseness is the safe direction —
# a false positive only means this guard stays quiet about one route, whereas a
# false negative would demand a bogus KNOWN_GAPS entry for a route that is in
# fact wired up, which is how a list like that rots.
_TS_PATH_RE = re.compile(r"(/v1/[^\"'`\s?]*)")
_TS_BASE_PATH_RE = re.compile(r"""\$\{([A-Za-z_][A-Za-z0-9_]*)\}([^"'`\s?]*)""")


def _normalise_backend(path: str) -> str:
    """Collapse FastAPI path params: ``/x/{ioc_id}`` -> ``/x/{}``."""
    return _PARAM_RE.sub("{}", path).rstrip("/") or "/"


def _normalise_frontend(path: str) -> tuple[str, bool]:
    """Collapse a TS path literal, and say whether its tail was cut off.

    Order matters: ``${id}`` must be consumed as a *whole* interpolation
    before the brace rule runs, or ``{id}`` gets eaten first and leaves a
    stray ``$`` that never matches the backend form.

    Returns ``(path, truncated)``. ``truncated`` is True when the literal ran
    into an interpolation this can't resolve — ``/v1/auth/mfa/${path}``, where
    the client picks the final segment at runtime. Those cover everything
    beneath them; a fully static literal covers only itself. Keeping the two
    apart is what stops the loose case from swallowing real gaps.
    """
    path = _TS_PARAM_RE.sub("{}", path)
    truncated = "$" in path
    if truncated:
        path = path[: path.index("$")]
    # An interpolation glued onto a segment rather than forming one —
    # `/v1/audit/lineage${qs}` -> `/audit/lineage{}` — is a query string, not
    # a path parameter. Drop it and mark the path as truncated.
    while path.endswith("{}") and not path.endswith("/{}"):
        path = path[:-2]
        truncated = True
    path = _PARAM_RE.sub("{}", path)
    return (path.rstrip("/") or "/", truncated)


def _backend_routes() -> list[tuple[str, str]]:
    """Every ``(METHOD, normalised path)`` declared under ``api/v1``."""
    routes: list[tuple[str, str]] = []
    for f in sorted(_API_DIR.glob("*.py")):
        src = f.read_text()
        m = _ROUTER_PREFIX_RE.search(src)
        prefix = m.group(1) if m else ""
        for rm in _ROUTE_RE.finditer(src):
            routes.append((rm.group(1).upper(), _normalise_backend(prefix + rm.group(2))))
    return routes


def _frontend_paths() -> tuple[set[str], set[str]]:
    """Normalised API paths the SPA actually calls.

    Scans all of ``frontend/src`` rather than just ``api/``: a route reached
    from a store or a component is still reached. Resolves the per-module
    ``const BASE = "/v1/..."`` indirection, since most clients build their
    URLs as ``` `${BASE}/runs` ```.
    """
    exact: set[str] = set()
    dynamic: set[str] = set()
    sources = sorted(_FRONTEND_SRC.rglob("*.ts")) + sorted(_FRONTEND_SRC.rglob("*.tsx"))
    for f in sources:
        src = f.read_text()
        consts = {name: val for name, val in _BASE_CONST_RE.findall(src)}
        literals: list[str] = [pm.group(1) for pm in _TS_PATH_RE.finditer(src)]
        for pm in _TS_BASE_PATH_RE.finditer(src):
            base = consts.get(pm.group(1))
            if base:
                literals.append(base + pm.group(2))
        for lit in literals:
            path, truncated = _normalise_frontend(lit)
            (dynamic if truncated else exact).add(path)

    def _strip_v1(paths: set[str]) -> set[str]:
        # The routers don't carry the /v1 the client sends.
        return {p[len("/v1") :] or "/" for p in paths if p.startswith("/v1")} | paths

    return _strip_v1(exact), _strip_v1(dynamic)


def _static_prefix(path: str) -> str:
    """The part of a path before its first parameter.

    ``/containment/safelist/{}`` -> ``/containment/safelist``.
    """
    return path.split("{}", 1)[0].rstrip("/") or "/"


def _segments_match(route: str, candidate: str) -> bool:
    """Compare two paths segment-by-segment, ``{}`` matching any one segment.

    Segment count must agree. That is what keeps siblings apart: the wired
    ``/cti/proposals/{}/compose-pr`` must NOT vouch for the unwired
    ``/cti/proposals/{}/pr-outcome`` just because they share a prefix. An
    earlier prefix-equality rule did exactly that and silently marked a real
    gap as reached.
    """
    a = route.strip("/").split("/")
    b = candidate.strip("/").split("/")
    if len(a) != len(b):
        return False
    return all(x == y or x == "{}" or y == "{}" for x, y in zip(a, b))


def _is_reachable(path: str, frontend: tuple[set[str], set[str]]) -> bool:
    """Whether the SPA appears to call this route.

    Two known limits, stated so a pass isn't read as more than it is:

    * Matching is at PATH granularity, not per-verb — a client's HTTP method
      isn't reliably recoverable from a path literal. This catches a whole
      capability shipping dark, not a missing verb on a wired resource.
    * A literal whose tail is built at runtime (``/auth/mfa/${path}``) vouches
      for everything beneath it, so an unreached sub-route of an
      already-wired family can hide. Narrowing that would mean interpreting
      arbitrary TS expressions.
    """
    exact, dynamic = frontend
    if path in exact:
        return True
    if any(_segments_match(path, fp) for fp in exact):
        return True
    # A literal cut off at an unresolvable interpolation stands in for exactly
    # the one segment it couldn't resolve —
    # /containment/safelist/${encodeURIComponent(id)} reaches the by-id route,
    # but NOT a deeper /containment/safelist/{}/something-else.
    depth = len(path.strip("/").split("/"))
    return any(
        # Truncated at a query string: `${BASE}/coverage-map${qs}` -> same path.
        path == dp
        # Truncated at a path segment: one level deeper, and no further.
        or (path.startswith(dp + "/") and depth == len(dp.strip("/").split("/")) + 1)
        for dp in dynamic
    )


# --------------------------------------------------------------------------- #
# The ratchet
# --------------------------------------------------------------------------- #


def _key(method: str, path: str) -> str:
    return f"{method} {path}"


def test_every_route_is_reachable_or_declared():
    """A new route with no consumer fails here rather than shipping dark."""
    frontend = _frontend_paths()
    declared = set(NOT_BROWSER_CALLED) | set(KNOWN_GAPS)

    undeclared = [
        _key(m, p)
        for m, p in _backend_routes()
        if not _is_reachable(p, frontend) and _key(m, p) not in declared
    ]

    assert not undeclared, (
        "These routes have no frontend caller and are not declared:\n  "
        + "\n  ".join(sorted(undeclared))
        + "\n\nWire one up in frontend/src/api/, or add it to NOT_BROWSER_CALLED "
        "(if a browser genuinely never calls it) or KNOWN_GAPS (if it is real "
        "debt). Prefer wiring it up — see this module's docstring."
    )


def test_known_gaps_are_still_gaps():
    """A fixed gap must leave the list, so it can't rot into an exemption."""
    frontend = _frontend_paths()
    backend = {_key(m, p) for m, p in _backend_routes()}

    now_reachable = [
        key
        for key in KNOWN_GAPS
        if key in backend and _is_reachable(key.split(" ", 1)[1], frontend)
    ]
    assert not now_reachable, (
        "These are listed in KNOWN_GAPS but now have a frontend caller:\n  "
        + "\n  ".join(sorted(now_reachable))
        + "\n\nDelete them from KNOWN_GAPS — the list only shrinks."
    )


def test_declared_entries_still_exist():
    """A stale declaration for a deleted route is dead weight; drop it."""
    backend = {_key(m, p) for m, p in _backend_routes()}
    stale = sorted((set(NOT_BROWSER_CALLED) | set(KNOWN_GAPS)) - backend)
    assert not stale, (
        "These are declared but no longer exist as routes:\n  "
        + "\n  ".join(stale)
        + "\n\nRemove the stale entries."
    )


def test_the_two_lists_do_not_overlap():
    """ "Correct by design" and "debt with a name" are different claims."""
    overlap = sorted(set(NOT_BROWSER_CALLED) & set(KNOWN_GAPS))
    assert not overlap, f"Declared in both lists, which contradicts itself: {overlap}"


def test_extraction_actually_found_something():
    """Guard the guard: a broken regex would make every assertion above pass."""
    routes = _backend_routes()
    exact, dynamic = _frontend_paths()
    # Deliberately loose — these only catch "the parser returned nothing",
    # which is the failure mode that would silently disarm this whole module.
    assert len(routes) > 100, f"only found {len(routes)} backend routes; parser broken?"
    assert len(exact | dynamic) > 50, (
        f"only found {len(exact | dynamic)} frontend paths; parser broken?"
    )


# --------------------------------------------------------------------------- #
# The matcher itself
# --------------------------------------------------------------------------- #
#
# The assertions above all pass when nothing is wrong, which is exactly when a
# broken matcher also passes. These pin the behaviour directly, using the real
# cases that shaped it while this file was being written.


def _fe(exact: set[str] | None = None, dynamic: set[str] | None = None):
    return (exact or set(), dynamic or set())


def test_matcher_catches_an_unwired_route():
    """The whole point: a route nothing calls is not reachable."""
    assert not _is_reachable("/validation/emulate", _fe({"/validation/runs"}))


def test_matcher_does_not_let_a_sibling_vouch_for_a_gap():
    """A wired sibling must not cover an unwired one.

    This is the bug an earlier prefix-equality rule had: it marked
    ``/cti/proposals/{}/pr-outcome`` reachable because
    ``/cti/proposals/{}/compose-pr`` was wired.
    """
    frontend = _fe({"/cti/proposals/{}/compose-pr"})
    assert _is_reachable("/cti/proposals/{}/compose-pr", frontend)
    assert not _is_reachable("/cti/proposals/{}/pr-outcome", frontend)


def test_matcher_treats_a_client_param_as_any_segment():
    """``/auth/mfa/${path}`` reaches the literal sub-routes beneath it."""
    assert _is_reachable("/auth/mfa/enroll", _fe({"/auth/mfa/{}"}))


def test_matcher_accepts_a_runtime_built_id():
    """``/safelist/${encodeURIComponent(id)}`` reaches the by-id route."""
    assert _is_reachable("/containment/safelist/{}", _fe(dynamic={"/containment/safelist"}))


def test_a_truncated_literal_does_not_vouch_arbitrarily_deep():
    """One segment past a truncation, not the whole subtree."""
    frontend = _fe(dynamic={"/cti/proposals"})
    assert _is_reachable("/cti/proposals/{}", frontend)
    assert not _is_reachable("/cti/proposals/{}/pr-outcome", frontend)


def test_a_query_string_truncation_still_matches_its_own_route():
    """``/coverage-map${qs}`` is the same route, not a child of it."""
    assert _is_reachable("/validation/coverage-map", _fe(dynamic={"/validation/coverage-map"}))


def test_segment_counts_must_agree():
    assert not _is_reachable("/mitre/gaps", _fe({"/mitre"}))
    assert not _is_reachable("/mitre", _fe({"/mitre/gaps"}))
