"""Every API route is reachable from the UI, at the URL a browser really sends.

Three consecutive slices found backend capability shipping with no consumer:
``POST /validation/emulate`` and ``GET /validation/coverage-map`` had no
frontend at all, and the TLP policy evaluator was never called on a real
egress. Each was found a release *after* it landed. Green CI said nothing,
because every layer was individually correct — the route worked, the service
worked, the tests passed. What was missing was the wiring, and nothing checks
for missing wiring.

This is the check. A route mounted on the app must either:

* be called from ``frontend/src`` at its **real mounted URL**, or
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

**Both directions are checked, and the second one is why this file was
rewritten (#482).** Until then the guard compared route *shapes* against the
FastAPI routers, which do not carry the ``/v1`` the app is mounted under. A
client whose base was ``/cloud`` instead of ``/v1/cloud`` therefore matched the
``/cloud/...`` router shape and passed, while every real browser request 404'd
on ``/api/cloud/...`` (#117 / PR #515 — the feature shipped completely
non-functional, and this guard vouched for it). So now:

* the route inventory is the **mounted** path taken from the live
  ``create_app()`` object — ``/api/v1/cloud/...``, not ``/cloud/...``;
* every frontend call site is resolved into the **full path the browser would
  request** — ``client.ts``'s ``BASE_URL`` (``/api``) plus the literal — and
  must land on a mounted route (:func:`test_every_frontend_call_hits_a_route`),
  with :data:`CALLS_WITHOUT_A_ROUTE` as the named-debt list for that direction.

A client that omits ``/v1`` now fails both tests. The rewrite found two live
ones on ``main``: the TAXII feeds panel (``/taxii/feeds``, fixed in the same
change) and a chat-history call to an endpoint that was never built.

Everything this still cannot see is listed under "What is still NOT covered"
below. Read it before treating a pass as proof the feature works.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

_REPO = Path(__file__).resolve().parents[2]
_API_DIR = _REPO / "backend" / "btagent_backend" / "api" / "v1"
_FRONTEND_SRC = _REPO / "frontend" / "src"
_CLIENT_TS = _FRONTEND_SRC / "api" / "client.ts"

# --------------------------------------------------------------------------- #
# Declared exceptions
# --------------------------------------------------------------------------- #

# Endpoints no browser fetch will ever hit. Correct by design.
# Keys stay router-relative (``/webhooks/splunk``, not
# ``/api/v1/webhooks/splunk``) so they read like the route declaration they
# refer to; the mount prefix is added by the guard, not by hand.
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
    # Reclassified from KNOWN_GAPS after the buildable gaps were all wired
    # (#478-#487). These two are design statements, not unfinished work —
    # the distinction this file's docstring insists on, argued here so the
    # move is reviewable rather than a silencing:
    #
    # /mitre/seed reloads the ATT&CK matrix from the vendored STIX bundle. It
    # is a deployment bootstrap in the same family as alembic migrations and
    # infra/scripts/seed-data.py: run once per deployment/refresh by an
    # operator, idempotent-by-reload, minutes-long, and org-independent
    # (the matrix is global). A button for it would put a long-running
    # global-state reload one misclick away from an admin console that
    # otherwise edits per-org state. If a genuine in-product "update the
    # matrix" workflow is ever wanted, that is a job + progress surface —
    # designed as such — not this endpoint behind a button.
    "POST /mitre/seed": "deployment-time matrix bootstrap, run by operators like a migration",
    # /auth/refresh serves non-SPA clients (CLI/mobile carrying body tokens)
    # and the cookie-rotation path with its theft-detection family logic.
    # The SPA deliberately rides the httpOnly access-cookie lifetime
    # (Phase C2) and re-authenticates at expiry; silent renewal was a
    # considered non-goal, since bounded session length is part of the
    # security posture for an IR console. UAT exercises the endpoint
    # directly, so it is tested — it is just not *browser* capability.
    "POST /auth/refresh": "CLI/mobile token rotation; the SPA rides the cookie lifetime by design",
    # E2E test-seed routes (api/v1/test_seed.py): called by Playwright over
    # HTTP to stage stores that have no product write path (behavioral scan /
    # pattern scan outputs). They 404 outside BTAGENT_ENV=test, so no browser
    # in a real deployment can ever reach them — by design, not debt.
    "POST /behavioral/test/entities": "E2E seed; 404s outside BTAGENT_ENV=test, Playwright-only",
    "POST /behavioral/test/outliers": "E2E seed; 404s outside BTAGENT_ENV=test, Playwright-only",
    "POST /pattern/test/proposals": "E2E seed; 404s outside BTAGENT_ENV=test, Playwright-only",
}

# Capability that exists server-side and cannot be reached from the product.
# Each entry is debt. Delete the line when you wire it up — leaving it here
# after the fact fails this test on purpose.
# Entries are deliberately KNOWN_GAPS rather than NOT_BROWSER_CALLED when a
# browser *should* call the route — claiming otherwise would be a lie, and a
# hollow ``frontend/src/api`` client with no component behind it would silence
# this check without making the capability reachable (the exact failure mode
# this file exists to catch). Name the debt instead; delete the line when the
# screen lands.
KNOWN_GAPS: dict[str, str] = {}

# The mirror image of KNOWN_GAPS: a call the SPA makes that no route serves.
# Keyed by the **effective** path (what the browser puts on the wire), because
# that is the thing that 404s.
#
# Read the reason before you add a line here. This list is NOT for a client
# whose base path is wrong — a base missing ``/v1`` is a one-line typo in the
# client, and listing it here would recreate exactly the #515 failure with a
# test blessing it. It is for a client that names capability the backend does
# not have, where the fix is a backend route and therefore a separate change.
CALLS_WITHOUT_A_ROUTE: dict[str, str] = {
    # Found by this rewrite (#482). ``agentStore.loadHistory`` calls it on every
    # investigation open and swallows the failure ("History may not exist yet
    # for new investigations"), so the chat transcript silently never restores.
    # The endpoint was never built: investigations.py has /chat but no /history.
    # Fixing it means adding a backend route, not editing the client.
    "/api/v1/investigations/{}/history": (
        "no such backend route; agentStore.loadHistory catches the 404 and "
        "shows an empty transcript"
    ),
}

# --------------------------------------------------------------------------- #
# What is still NOT covered, stated so a pass isn't read as more than it is
# --------------------------------------------------------------------------- #
#
# Now covered (was the #117/#515 blind spot): a client base that omits ``/v1``,
# or any other wrong prefix, because both sides are compared as full mounted
# URLs including ``client.ts``'s ``/api``.
#
# Still NOT covered — all of it static-analysis reach, not request reality:
#
# * **Paths this cannot statically resolve.** ``api.get(endpoint)`` where
#   ``endpoint`` is built by a helper, a base held in something other than a
#   module-level ``const X = "/..."``, or a path assembled across statements.
#   Those call sites are simply not seen — they can neither prove a route
#   reachable nor be caught sending a wrong path.
# * **Verb granularity.** Matching is per-path, not per-method: a client's HTTP
#   verb is not reliably recoverable from a path literal. A capability shipping
#   dark is caught; a missing verb on an already-wired resource is not.
# * **Mentions vs calls.** A ``/v1/...`` path written in a doc comment counts as
#   a caller for the route→UI direction (deliberate looseness — see
#   ``_PATH_MENTION_RE``). It cannot cause a false *failure*, but it can keep
#   this guard quiet about a route whose only "consumer" is prose.
# * **Query strings, request bodies, auth, RBAC.** A path that resolves can
#   still 400/403 at runtime. Only routing is checked here.
# * **The dev/ingress hop.** ``vite.config.ts`` and ``infra/nginx/nginx.conf``
#   both forward ``/api`` unrewritten; if either ever rewrites the prefix, this
#   guard would not notice.
# * **``VITE_API_BASE_URL``.** Only the ``?? "/api"`` fallback is read. A
#   deployment that sets the env var to an absolute origin is not modelled.
# * **Frontend test files.** ``__tests__`` / ``*.test.ts`` are skipped: their
#   fixture paths (``/v1/anything``) are neither real calls nor evidence that a
#   route is wired.
#
# The honest summary: this proves a request would *route*, not that the feature
# works. Only a real request does that.


# --------------------------------------------------------------------------- #
# The two prefixes that have to agree
# --------------------------------------------------------------------------- #

# ``const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";``
_BASE_URL_RE = re.compile(r'const\s+BASE_URL\s*=[^;]*?\?\?\s*"([^"]+)"')


@lru_cache(maxsize=1)
def _client_base_url() -> str:
    """The prefix ``frontend/src/api/client.ts`` puts in front of every path.

    Read from the source rather than hard-coded: if the SPA's base moves, the
    guard has to move with it, and a silently stale constant here would put us
    straight back in the #515 hole.
    """
    m = _BASE_URL_RE.search(_CLIENT_TS.read_text())
    assert m, "could not read BASE_URL out of frontend/src/api/client.ts"
    return m.group(1).rstrip("/")


@lru_cache(maxsize=1)
def _mount_prefix() -> str:
    """Where the v1 router is actually mounted (``/api/v1``)."""
    from btagent_backend.api.v1.router import api_v1_router

    return api_v1_router.prefix.rstrip("/")


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

_ROUTER_PREFIX_RE = re.compile(r'APIRouter\((?:[^)]*?)prefix="([^"]+)"', re.S)
_ROUTE_RE = re.compile(r'@router\.(get|post|put|patch|delete)\(\s*"([^"]*)"')
_PARAM_RE = re.compile(r"\{[^}]+\}")
# Any module-level ``const SOMETHING = "/..."`` — clients name these BASE,
# IDENTITY_BASE, etc., so match on the value rather than the identifier. NOT
# restricted to values starting with ``/v1``: a base *missing* the ``/v1`` is
# precisely the defect this file now has to see (#515).
_BASE_CONST_RE = re.compile(r'^const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(/[^"]*)"', re.M)
# ``${BASE}/findings/${id}`` — an interpolated base plus a literal tail.
_TS_BASE_PATH_RE = re.compile(r"""\$\{([A-Za-z_][A-Za-z0-9_]*)\}([^"'`\s?]*)""")
# A bare path literal handed straight to the client: ``api.post("/v1/x", body)``.
# The optional ``<...>`` is the TS type argument (``api.get<Foo<Bar>>(...)``).
_API_CALL_RE = re.compile(
    r"""\bapi\.(?:get|post|put|patch|delete)\s*(?:<[^(]*?>)?\s*\(\s*(?:`([^`]*)`|"([^"]*)")""",
    re.S,
)
# Any ``/v1/...`` occurrence. Deliberately NOT anchored to a quote: clients
# build URLs as ``${BASE_URL}/v1/auth/login`` and ``/api/v1/audit/export``, so
# requiring a preceding quote loses them. The looseness is the safe direction —
# a false positive only means this guard stays quiet about one route, whereas a
# false negative would demand a bogus KNOWN_GAPS entry for a route that is in
# fact wired up, which is how a list like that rots. Note it starts at ``/v1``,
# so a ``/api/v1/...`` mention yields the client-relative ``/v1/...`` form.
_PATH_MENTION_RE = re.compile(r"(/v1/[^\"'`\s?]*)")


class _Call(NamedTuple):
    """A resolved SPA request path."""

    origin: str  # repo-relative source file
    raw: str  # the literal as written, base-const substituted
    path: str  # normalised, client-relative: /v1/hunt/findings/{}
    truncated: bool  # the tail was built at runtime and had to be cut


def _normalise_backend(path: str) -> str:
    """Collapse FastAPI path params: ``/x/{ioc_id}`` -> ``/x/{}``."""
    return _PARAM_RE.sub("{}", path).rstrip("/") or "/"


def _collapse_interpolations(literal: str) -> tuple[str, bool]:
    """Replace each ``${...}`` with ``{}``, brace-counting so nesting survives.

    ``${buildQuery(params ?? {})}`` is one interpolation, not one-and-a-bit: a
    naive ``\\$\\{[^}]*\\}`` stops at the inner ``}`` and leaves ``{})}`` glued
    to the path, which then matches nothing. Returns ``(text, cut)``, where
    ``cut`` means an interpolation never closed inside the captured text (the
    literal was clipped mid-expression) and everything from there is dropped.
    """
    out: list[str] = []
    i = 0
    while i < len(literal):
        if literal.startswith("${", i):
            depth = 0
            j = i + 1
            while j < len(literal):
                if literal[j] == "{":
                    depth += 1
                elif literal[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= len(literal):
                return "".join(out), True
            out.append("{}")
            i = j + 1
        else:
            out.append(literal[i])
            i += 1
    return "".join(out), False


def _normalise_frontend(path: str) -> tuple[str, bool]:
    """Collapse a TS path literal, and say whether its tail was cut off.

    Returns ``(path, truncated)``. ``truncated`` is True when the literal ran
    into something built at runtime that this can't resolve — a query string,
    or an interpolation glued onto a segment rather than forming one. Those
    cover everything beneath them; a fully static literal covers only itself.
    Keeping the two apart is what stops the loose case from swallowing real
    gaps.
    """
    path, truncated = _collapse_interpolations(path)
    if "?" in path:
        # A query string is not part of the route.
        path = path.split("?", 1)[0]
        truncated = True
    # An interpolation glued onto a segment rather than forming one —
    # `/v1/connectors${suffix}` -> `/v1/connectors{}` — is a suffix built at
    # runtime, not a path parameter. Keep the segment's static head (that part
    # IS the route), drop everything after it, and say the tail was cut.
    kept: list[str] = []
    for seg in path.strip("/").split("/") if path.strip("/") else []:
        if "{}" in seg and seg != "{}":
            truncated = True
            head = seg.split("{}", 1)[0]
            if head:
                kept.append(head)
            break
        kept.append(seg)
    path = "/" + "/".join(kept)
    path = _PARAM_RE.sub("{}", path)
    return (path.rstrip("/") or "/", truncated)


def _effective(client_relative: str) -> str:
    """The full path the browser puts on the wire.

    ``client.ts`` prepends ``BASE_URL`` to everything that isn't absolute, so
    ``/v1/hunt/findings`` leaves as ``/api/v1/hunt/findings``. This one line is
    the whole difference between the shape match that missed #515 and a check
    against what the network actually sees.
    """
    return _client_base_url() + client_relative


@lru_cache(maxsize=1)
def _mounted_routes() -> tuple[tuple[str, str, str], ...]:
    """``(METHOD, mounted path, declared path)`` for the browser-facing API.

    Taken from the real application object, so the ``/api/v1`` prefix is the
    one FastAPI will actually serve rather than a prefix this test believes in.
    The declared (router-relative) path is carried alongside because that is
    what the two declaration lists above are keyed by, and what a reader
    grepping for ``@router.post("/seed")`` will find.

    The surface is "the v1 mount, plus the root-level health probes" — the
    routes a product feature can live behind. ``/metrics``, ``/api/docs`` and
    the WebSocket endpoints are infrastructure, not capability, and are not
    part of the ratchet.

    FastAPI ≥ 0.141 no longer flattens ``include_router`` children into the
    parent's ``.routes``: each include appends a lazy wrapper that holds the
    ``original_router`` plus an ``include_context.prefix`` (the includer's own
    prefix + the explicit ``prefix=`` argument, already accumulated at include
    time). A leaf's mounted path is therefore the sum of the context prefixes
    down the include chain plus the leaf's own path — which already carries the
    prefix of the ``APIRouter`` it was declared on. ``_walk`` handles both that
    shape and the old flat one, so this guard doesn't care which side of the
    drift CI resolves.
    """
    from btagent_backend.api.v1.router import health_router_root
    from btagent_backend.main import create_app

    prefix = _mount_prefix()
    root_paths = {r.path for r in health_router_root.routes}
    app = create_app()

    def _walk(routes: Iterable[object], acc: str) -> Iterator[tuple[str, set[str]]]:
        for route in routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if path and methods:
                yield acc + path, methods
                continue
            # WebSocket routes and mounts have no methods; a lazy include
            # wrapper has neither path nor methods but exposes the child.
            inner = getattr(route, "original_router", None)
            if inner is not None:
                ctx = getattr(route, "include_context", None)
                yield from _walk(inner.routes, acc + getattr(ctx, "prefix", ""))

    out: set[tuple[str, str, str]] = set()
    for path, methods in _walk(app.routes, ""):
        if path.startswith(prefix + "/"):
            declared = path[len(prefix) :]
        elif path in root_paths:
            declared = path
        else:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue  # added by Starlette, never declared by us
            out.add((method, _normalise_backend(path), _normalise_backend(declared)))
    return tuple(sorted(out))


def _declared_routes() -> list[tuple[str, str]]:
    """Every ``(METHOD, router-relative path)`` written in ``api/v1/*.py``.

    Kept as a *static* read of the source so it can be cross-checked against
    the mounted inventory: a router file nobody remembered to
    ``include_router`` shows up here and not there.
    """
    routes: list[tuple[str, str]] = []
    for f in sorted(_API_DIR.glob("*.py")):
        src = f.read_text()
        m = _ROUTER_PREFIX_RE.search(src)
        prefix = m.group(1) if m else ""
        for rm in _ROUTE_RE.finditer(src):
            routes.append((rm.group(1).upper(), _normalise_backend(prefix + rm.group(2))))
    return routes


def _call_literals(src: str) -> list[str]:
    """Path literals this module hands to the HTTP client, bases resolved.

    Two forms, both unambiguous requests rather than prose:

    * ``` `${BASE}/findings/${id}` ``` with ``BASE`` a module-level string
      const — how nearly every client in ``frontend/src/api`` is written, and
      where a wrong base hides;
    * ``api.get("/v1/containment/safelist")`` — a bare literal argument.

    A literal that starts with an interpolation this can't resolve is dropped:
    unresolvable is not the same as wrong, and inventing a path for it would
    manufacture a failure. That gap is stated in the limits block above.
    """
    consts = dict(_BASE_CONST_RE.findall(src))
    out: list[str] = []
    for pm in _TS_BASE_PATH_RE.finditer(src):
        base = consts.get(pm.group(1))
        if base:
            out.append(base + pm.group(2))
    for am in _API_CALL_RE.finditer(src):
        lit = am.group(1) or am.group(2) or ""
        if lit.startswith("${") and "}" in lit:
            resolved = consts.get(lit[2 : lit.index("}")])
            if resolved:
                lit = resolved + lit[lit.index("}") + 1 :]
        if lit.startswith("/"):
            out.append(lit)
    # The two forms overlap on ``api.get(`${BASE}/x`)`` — same call, seen twice.
    return list(dict.fromkeys(out))


def _is_test_source(path: Path) -> bool:
    """Vitest files invent paths (``/v1/anything``) to exercise the client.

    They are not product call sites, and must not vouch for a route either —
    a route whose only caller is a test fixture is still unreachable capability.
    """
    return "__tests__" in path.parts or ".test." in path.name or ".spec." in path.name


def _sources() -> list[Path]:
    found = sorted(_FRONTEND_SRC.rglob("*.ts")) + sorted(_FRONTEND_SRC.rglob("*.tsx"))
    return [p for p in found if not _is_test_source(p)]


@lru_cache(maxsize=1)
def _frontend_calls() -> tuple[_Call, ...]:
    """Every SPA request path this can resolve, with the file it came from."""
    calls: list[_Call] = []
    for f in _sources():
        origin = str(f.relative_to(_REPO))
        for lit in _call_literals(f.read_text()):
            path, truncated = _normalise_frontend(lit)
            calls.append(_Call(origin, lit, path, truncated))
    return tuple(calls)


@lru_cache(maxsize=1)
def _frontend_paths() -> tuple[frozenset[str], frozenset[str]]:
    """Full request paths the SPA appears to issue: ``(exact, dynamic)``.

    Scans all of ``frontend/src`` rather than just ``api/``: a route reached
    from a store or a component is still reached. Everything is returned as the
    **effective** path — ``BASE_URL`` included — so it can be compared against
    mounted routes directly.
    """
    exact: set[str] = set()
    dynamic: set[str] = set()

    # (The interim ``_strip_v1`` tightening from #523 is superseded here: a
    # base missing ``/v1`` now resolves to a full URL no mounted route serves,
    # which fails the sharper ``test_every_frontend_call_hits_a_route``.)
    for call in _frontend_calls():
        (dynamic if call.truncated else exact).add(_effective(call.path))

    for f in _sources():
        for lit in _PATH_MENTION_RE.findall(f.read_text()):
            path, truncated = _normalise_frontend(lit.rstrip(".,;:)"))
            # ``mirrors api/v1/notifications.py`` is prose about a module, not
            # a URL. No route has a dot in a segment, so this can only ever
            # discard noise — but noise in this set is a route quietly vouched
            # for by a comment, which is worth not having.
            if any("." in seg for seg in path.split("/")):
                continue
            (dynamic if truncated else exact).add(_effective(path))

    return frozenset(exact), frozenset(dynamic)


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


def _is_reachable(path: str, frontend: tuple[frozenset[str], frozenset[str]]) -> bool:
    """Whether the SPA appears to call this route, at this exact path.

    ``path`` is the mounted path (``/api/v1/hunt/findings``) and the candidates
    are effective request paths, so a client that drops ``/v1`` no longer
    matches anything — the #515 defect this direction of the check exists for.
    """
    exact, dynamic = frontend
    if path in exact:
        return True
    if any(_segments_match(path, fp) for fp in exact):
        return True
    # A literal cut off at a runtime-built tail stands in for exactly the one
    # segment it couldn't resolve — `/v1/connectors${suffix}` reaches
    # /connectors and, if `suffix` turns out to name one, a single segment
    # below it, but NOT a whole subtree.
    depth = len(path.strip("/").split("/"))
    return any(
        # Truncated at a query string: `${BASE}/coverage-map${qs}` -> same path.
        path == dp
        # Truncated at a path segment: one level deeper, and no further.
        or (path.startswith(dp + "/") and depth == len(dp.strip("/").split("/")) + 1)
        for dp in dynamic
    )


def _hits_a_route(call: _Call, mounted: frozenset[str]) -> bool:
    """Whether a resolved client path lands on something the app serves.

    The mirror image of :func:`_is_reachable`, and the direction that catches a
    wrong base path. A truncated literal is allowed to match a deeper route,
    since its tail is chosen at runtime: ``/v1/connectors${suffix}`` is a call
    to ``/connectors`` if ``suffix`` is a query string and to something below it
    if it is a path. Either way the *base* is checked, which is the point.
    """
    target = _effective(call.path)
    if any(_segments_match(mp, target) for mp in mounted):
        return True
    return call.truncated and any(mp.startswith(target + "/") for mp in mounted)


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
        f"{_key(m, decl)}  (mounted at {mounted})"
        for m, mounted, decl in _mounted_routes()
        if not _is_reachable(mounted, frontend) and _key(m, decl) not in declared
    ]

    assert not undeclared, (
        "These routes have no frontend caller and are not declared:\n  "
        + "\n  ".join(sorted(undeclared))
        + "\n\nWire one up in frontend/src/api/, or add it to NOT_BROWSER_CALLED "
        "(if a browser genuinely never calls it) or KNOWN_GAPS (if it is real "
        "debt). Prefer wiring it up — see this module's docstring.\n"
        "If the route IS wired, check the client's base path: it must carry "
        f"the '/v1' the app is mounted under ({_mount_prefix()}), because "
        f"client.ts already prepends '{_client_base_url()}'."
    )


def test_every_frontend_call_hits_a_route():
    """The #515 direction: a client that asks for the wrong URL fails here.

    ``test_every_route_is_reachable_or_declared`` asks "does anything call this
    route". This asks the opposite and much sharper question: "does this call
    reach anything". A base of ``/cloud`` instead of ``/v1/cloud`` looks fine
    from the first direction only because the route also goes unclaimed and
    could be waved through with a KNOWN_GAPS line. From this direction it is
    unambiguous — the SPA is sending ``/api/cloud/...`` and nothing serves it.
    """
    mounted = frozenset(m for _, m, _ in _mounted_routes())
    unreachable = sorted(
        {
            f"{call.origin}: `{call.raw}` -> {_effective(call.path)}"
            for call in _frontend_calls()
            if not _hits_a_route(call, mounted)
            and _effective(call.path) not in CALLS_WITHOUT_A_ROUTE
        }
    )
    assert not unreachable, (
        "These frontend call sites resolve to a path the app does not serve, "
        "so they 404 in a browser:\n  "
        + "\n  ".join(unreachable)
        + f"\n\nclient.ts prepends '{_client_base_url()}' and the v1 router is "
        f"mounted at '{_mount_prefix()}', so a client base must include the "
        '\'/v1\' (e.g. "/v1/cloud", not "/cloud"). This is the #117/#515 '
        "defect: the feature shipped completely non-functional while a "
        "shape-only version of this guard passed."
    )


def test_known_gaps_are_still_gaps():
    """A fixed gap must leave the list, so it can't rot into an exemption."""
    frontend = _frontend_paths()
    by_key = {_key(m, decl): mounted for m, mounted, decl in _mounted_routes()}

    now_reachable = [
        key for key in KNOWN_GAPS if key in by_key and _is_reachable(by_key[key], frontend)
    ]
    assert not now_reachable, (
        "These are listed in KNOWN_GAPS but now have a frontend caller:\n  "
        + "\n  ".join(sorted(now_reachable))
        + "\n\nDelete them from KNOWN_GAPS — the list only shrinks."
    )


def test_unserved_calls_are_still_unserved():
    """Same ratchet, other direction: a served call must leave the list.

    Either the backend route landed or the client stopped asking; both mean
    the line is a stale exemption, and stale exemptions are how a guard rots.
    """
    mounted = frozenset(m for _, m, _ in _mounted_routes())
    by_path = {_effective(c.path): c for c in _frontend_calls()}
    fixed = sorted(
        key
        for key in CALLS_WITHOUT_A_ROUTE
        if key not in by_path or _hits_a_route(by_path[key], mounted)
    )
    assert not fixed, (
        "These are listed in CALLS_WITHOUT_A_ROUTE but are no longer broken "
        "calls (the route exists now, or nothing calls the path):\n  "
        + "\n  ".join(fixed)
        + "\n\nDelete them — the list only shrinks."
    )


def test_declared_entries_still_exist():
    """A stale declaration for a deleted route is dead weight; drop it."""
    mounted = {_key(m, decl) for m, _, decl in _mounted_routes()}
    stale = sorted((set(NOT_BROWSER_CALLED) | set(KNOWN_GAPS)) - mounted)
    assert not stale, (
        "These are declared but no longer exist as routes:\n  "
        + "\n  ".join(stale)
        + "\n\nRemove the stale entries."
    )


def test_the_two_lists_do_not_overlap():
    """ "Correct by design" and "debt with a name" are different claims."""
    overlap = sorted(set(NOT_BROWSER_CALLED) & set(KNOWN_GAPS))
    assert not overlap, f"Declared in both lists, which contradicts itself: {overlap}"


def test_every_declared_route_is_actually_mounted():
    """A router file nobody remembered to include is capability shipping dark.

    The static read of ``api/v1/*.py`` and the mounted inventory have to agree.
    They disagree when a whole ``include_router`` line is missing — the same
    class of wiring bug as an unwired frontend, one layer down.
    """
    mounted = {_key(m, decl) for m, _, decl in _mounted_routes()}
    unmounted = sorted({_key(m, p) for m, p in _declared_routes()} - mounted)
    assert not unmounted, (
        "These routes are declared in backend/btagent_backend/api/v1/ but are "
        "not mounted on the app:\n  "
        + "\n  ".join(unmounted)
        + "\n\nAdd the missing include_router() in api/v1/router.py."
    )


def test_extraction_actually_found_something():
    """Guard the guard: a broken regex would make every assertion above pass."""
    routes = _mounted_routes()
    exact, dynamic = _frontend_paths()
    calls = _frontend_calls()
    # Deliberately loose — these only catch "the parser returned nothing",
    # which is the failure mode that would silently disarm this whole module.
    assert len(routes) > 100, f"only found {len(routes)} mounted routes; parser broken?"
    assert len(exact | dynamic) > 50, (
        f"only found {len(exact | dynamic)} frontend paths; parser broken?"
    )
    assert len(calls) > 50, f"only resolved {len(calls)} frontend call sites; parser broken?"
    # The two prefixes are the whole point of the rewrite; if either stops
    # being readable, every full-path comparison below silently degrades into
    # the shape match that missed #515.
    assert _client_base_url() == "/api", _client_base_url()
    assert _mount_prefix() == "/api/v1", _mount_prefix()
    assert all(m.startswith(_mount_prefix() + "/") or m.startswith("/health") for _, m, _ in routes)


# --------------------------------------------------------------------------- #
# The matcher itself
# --------------------------------------------------------------------------- #
#
# The assertions above all pass when nothing is wrong, which is exactly when a
# broken matcher also passes. These pin the behaviour directly, using the real
# cases that shaped it while this file was being written.


def _fe(exact: set[str] | None = None, dynamic: set[str] | None = None):
    return (frozenset(exact or set()), frozenset(dynamic or set()))


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


def test_matcher_accepts_a_runtime_built_tail():
    """A literal cut off at a runtime tail reaches one segment below itself."""
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


# --------------------------------------------------------------------------- #
# The literal reader
# --------------------------------------------------------------------------- #
#
# What a literal collapses to decides what gets compared, so a silent mistake
# here is a silent hole in everything above. Each case below is a real client
# line from frontend/src/api.


def test_an_interpolated_id_becomes_one_wildcard_segment():
    assert _normalise_frontend("/v1/investigations/${id}/chat") == (
        "/v1/investigations/{}/chat",
        False,
    )


def test_a_nested_brace_interpolation_is_one_unit():
    """``${buildQuery(params ?? {})}`` — the inner ``{}`` must not end it.

    A naive ``\\$\\{[^}]*\\}`` stops at the inner brace and leaves ``{})}``
    stuck to the path, which then matches no route: the client looks broken
    when it isn't, and the fix would be to loosen the guard. Getting this right
    is what lets the loosening stay unnecessary.
    """
    assert _normalise_frontend("/v1/mitre/exercises${buildQuery(params ?? {})}") == (
        "/v1/mitre/exercises",
        True,
    )


def test_a_glued_suffix_keeps_its_own_segment():
    """``/v1/connectors${suffix}`` is a call to /connectors, not to /v1."""
    assert _normalise_frontend("/v1/connectors${suffix}") == ("/v1/connectors", True)


def test_a_query_string_is_not_part_of_the_route():
    assert _normalise_frontend("/v1/hunt/findings?${search.toString()}") == (
        "/v1/hunt/findings",
        True,
    )


def test_a_literal_clipped_mid_interpolation_is_truncated():
    """Template capture stops at a nested backtick: ``${qs ? `?${qs}` : ""}``."""
    assert _normalise_frontend("/v1/validation/runs${qs ? ") == ("/v1/validation/runs", True)


def test_a_module_base_const_is_resolved_into_the_call():
    src = 'const BASE = "/v1/hunt";\nreturn api.get<X>(`${BASE}/findings/${id}/suppress`);\n'
    assert _call_literals(src) == ["/v1/hunt/findings/${id}/suppress"]


def test_a_bare_literal_argument_is_read_too():
    src = 'return api.post<ExecutionResult>("/v1/containment/execute/bulk-block", {\n'
    assert _call_literals(src) == ["/v1/containment/execute/bulk-block"]


def test_an_unresolvable_endpoint_is_skipped_not_guessed():
    """``api.get(endpoint)`` is invisible here — stated in the limits block.

    Skipping is the only honest option: inventing a path for it would either
    vouch for a route nothing proves is called, or fail a call that is fine.
    """
    assert _call_literals("const endpoint = f(x);\nreturn api.get<T>(endpoint);\n") == []


# --------------------------------------------------------------------------- #
# The #515 regression: a wrong base path
# --------------------------------------------------------------------------- #
#
# A guard that cannot fail is worthless, so these run the real extraction over
# a client written both ways and pin the difference. The snippet is the shape
# of ``frontend/src/api/cloudContainment.ts``, whose first cut shipped with
# ``const BASE = "/cloud"``.

_CLOUD_CLIENT = """\
import api from "./client";

const BASE = "{base}";

export async function getCloudContainmentProposal(investigationId: string) {{
  return api.get<CloudContainmentProposal>(
    `${{BASE}}/investigations/${{investigationId}}/containment-proposal`,
  );
}}
"""


def _resolve_snippet(base: str) -> _Call:
    literals = _call_literals(_CLOUD_CLIENT.format(base=base))
    assert len(literals) == 1, literals
    path, truncated = _normalise_frontend(literals[0])
    return _Call("<snippet>", literals[0], path, truncated)


def test_a_client_base_missing_v1_is_caught():
    """``/cloud`` fails, ``/v1/cloud`` passes — on the real route table."""
    mounted = frozenset(m for _, m, _ in _mounted_routes())
    route = "/api/v1/cloud/investigations/{}/containment-proposal"
    assert route in mounted, "the #117 route moved; retarget this regression test"

    bad = _resolve_snippet("/cloud")
    good = _resolve_snippet("/v1/cloud")

    # What the browser would actually request in each case.
    assert _effective(bad.path) == "/api/cloud/investigations/{}/containment-proposal"
    assert _effective(good.path) == route

    assert not _hits_a_route(bad, mounted), (
        "a client base missing /v1 must not be treated as reachable — that is "
        "exactly what shipped in #515"
    )
    assert _hits_a_route(good, mounted)


def test_the_wrong_base_also_leaves_the_route_unreachable():
    """The other direction of the same defect, on the same route."""
    route = "/api/v1/cloud/investigations/{}/containment-proposal"
    assert not _is_reachable(route, _fe({"/api/cloud/investigations/{}/containment-proposal"}))
    assert _is_reachable(route, _fe({route}))


def test_the_old_shape_only_match_would_have_passed_the_bad_client():
    """Why #515 slipped through, pinned so the fix can't be undone quietly.

    The pre-#482 guard compared the router-relative shape (``/cloud/...``,
    because the routers don't carry ``/v1``) against the client literal with
    its base attached. For a ``/cloud`` base those two strings are equal — a
    match, and a green test, for a client the browser cannot use. The
    comparison is only sound once ``BASE_URL`` and the mount prefix are both
    in play, which is what :func:`_effective` and :func:`_mounted_routes` add.
    """
    declared = {d for _, _, d in _mounted_routes()}
    bad = _resolve_snippet("/cloud")
    assert bad.path in declared  # the old comparison: match, so "reachable"
    assert _effective(bad.path) not in {m for _, m, _ in _mounted_routes()}  # the truth
