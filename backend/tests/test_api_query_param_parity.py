"""Every query parameter the SPA sends exists on the route it sends it to.

``test_api_reachability`` proves a frontend call would *route*. Its own
"What is still NOT covered" list names the hole this file fills:

    **Query strings, request bodies, auth, RBAC.** A path that resolves can
    still 400/403 at runtime. Only routing is checked here.

#586 fell straight into it. ``IOCExportDialog`` sent the analyst's chosen TLP
ceiling as ``tlp_max``; ``GET /iocs/export`` declares ``tlp_level``. FastAPI
**drops an unknown query parameter silently** — no 422, no warning — so the
declared parameter fell back to its ``"green"`` default on every export. The
selection had no effect: bundles were marked TLP:GREEN regardless, and the org
egress policy was only ever evaluated at green. Every layer was individually
correct and every suite was green, because nothing compared the two lists of
names.

That silent-drop behaviour is what makes this worth a static guard rather than
a runtime test: there is no error to observe. A wrong parameter name is
indistinguishable from an omitted one, and an omitted one is indistinguishable
from "the caller wanted the default".

What is checked
---------------
Both of the shapes the SPA uses to build a query string, paired with the
endpoint literal in the same function:

* ``buildQuery(x)`` where ``x`` is an inline object literal — the keys are
  read directly;
* ``buildQuery(x)`` where ``x`` is a parameter with a declared interface type
  — the interface's field names are read from ``frontend/src`` (this is the
  #586 shape: ``ExportOptions.tlp_max``);
* ``searchParams.set("name", …)`` — the literal is read directly.

Each emitted name must appear in the FastAPI route's ``dependant.query_params``
for the mounted path, taken from the live ``create_app()`` object.

What is NOT checked, so a pass isn't read as more than it is
------------------------------------------------------------
* **Types and values.** ``?page=banana`` is a name this guard accepts and the
  API rejects. Only names are compared.
* **The other direction.** A route parameter no client sends is not flagged —
  that is usually a legitimate default, not a defect.
* **Dynamically built names.** A key assembled at runtime
  (``params[`filter_${k}`]``) is invisible, as is a spread of an object this
  cannot resolve.
* **Request bodies.** POST/PUT payload fields are a separate surface with a
  separate failure mode (Pydantic *does* reject unknown fields when configured
  to, so they are not silently dropped in the same way).
* **Interfaces resolved by name only.** If two interfaces share a name across
  files, the first one found wins.

The honest summary: this proves the SPA is *speaking parameter names the route
knows*, not that the request succeeds.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

_REPO = Path(__file__).resolve().parents[2]
_FRONTEND_SRC = _REPO / "frontend" / "src"
_API_CLIENT_DIR = _FRONTEND_SRC / "api"

# --------------------------------------------------------------------------- #
# Declared exceptions
# --------------------------------------------------------------------------- #

#: ``"<mounted path> <param>" -> what is actually broken.``
#:
#: Debt with a name, in the same spirit as ``test_api_reachability``'s
#: ``KNOWN_GAPS``: the list is allowed to exist, but it may only shrink. A new
#: mismatch fails; an entry that has since been fixed also fails, so the list
#: cannot rot into a permanent exemption.
#:
#: The bar for an entry is a *description of the breakage*, not a reason it is
#: acceptable. There is no "correct by design" category here — a query
#: parameter the route does not declare is discarded, full stop. Anything that
#: could be honestly justified belongs on the route instead.
#:
#: Everything below was found by this guard on the change that introduced it.
#: Four sibling dead parameters (``severity`` on investigations, ``search`` /
#: ``is_active`` / ``trigger_type`` on playbooks) had no caller at all and were
#: deleted in the same change rather than listed here.
KNOWN_GAPS: dict[str, str] = {
    "/api/v1/investigations search": (
        "the list page sends it and the route ignores it; InvestigationList "
        "filters client-side, so search only matches within the page already "
        "loaded rather than across the investigation set"
    ),
    # The three ``/iocs/export`` entries this list shipped with — ``format``,
    # ``type`` and ``confidence_min`` — are gone because the route now declares
    # them. ``test_exemption_list_only_holds_live_entries`` is what forced
    # their removal: leaving a fixed gap listed fails just as loudly as a new
    # one appearing, which is the half of a ratchet that keeps it honest.
}

# A parser this simple could match nothing and pass vacuously. The floors are
# set below the real counts at the time of writing (13 buildQuery call sites,
# 20 resolved endpoint/param pairs) so ordinary additions do not trip them.
_MIN_CALL_SITES = 8
_MIN_PAIRS = 12


class Emitted(NamedTuple):
    """One query parameter the SPA sends to one endpoint."""

    endpoint: str  # frontend literal, e.g. "/v1/iocs/export"
    param: str
    source: str  # "file.ts:12"


# --------------------------------------------------------------------------- #
# Backend side: what each mounted route actually declares
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def _route_query_params() -> dict[str, frozenset[str]]:
    """``{mounted path: {declared query parameter names}}``.

    Read off the live application object for the same reason
    ``test_api_reachability`` does: a hand-maintained inventory would drift,
    and a stale one here would put us back in the hole this file exists to
    close.
    """
    from btagent_backend.main import create_app

    app = create_app()

    def _walk(routes: Iterable[object], acc: str) -> Iterator[tuple[str, object]]:
        for route in routes:
            path = getattr(route, "path", None)
            if path and getattr(route, "methods", None):
                yield acc + path, route
                continue
            inner = getattr(route, "original_router", None)
            if inner is not None:
                ctx = getattr(route, "include_context", None)
                yield from _walk(inner.routes, acc + getattr(ctx, "prefix", ""))

    found: dict[str, set[str]] = {}
    for path, route in _walk(app.routes, ""):
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        # ``alias`` is the name on the wire, ``name`` is the Python parameter.
        # They differ whenever a route declares ``Query(..., alias="status")``,
        # and it is the alias a browser sends — comparing against ``name``
        # would flag every aliased parameter as undeclared.
        names = {q.alias or q.name for q in dependant.query_params}
        # A path can carry several methods; union them. Query-name typos are
        # what we're after, and those are not verb-specific.
        found.setdefault(path, set()).update(names)
    return {path: frozenset(names) for path, names in found.items()}


# --------------------------------------------------------------------------- #
# Frontend side: what the SPA emits
# --------------------------------------------------------------------------- #

#: ``const endpoint = `/v1/iocs/export${buildQuery(options)}`;`` and the
#: ``api.get(`/v1/...${buildQuery(...)}`)`` form, which some modules use
#: without the intermediate variable.
_BUILD_QUERY_RE = re.compile(
    r"`(?P<path>/v1/[^`$]*)\$\{buildQuery\(\s*(?P<arg>.*?)\s*\)\}",
    re.DOTALL,
)

#: ``export interface ExportOptions { … }`` / ``interface Foo { … }``
_INTERFACE_RE = re.compile(r"(?:export\s+)?interface\s+(\w+)\s*\{(.*?)\n\}", re.DOTALL)

#: A field line inside an interface body: ``tlp_level?: TLP;``
_FIELD_RE = re.compile(r"^\s*(\w+)\??\s*:", re.MULTILINE)

#: A key inside an inline object literal: ``{ q: query, page_size: 1000 }``
_LITERAL_KEY_RE = re.compile(r"(\w+)\s*:")

#: ``params: ListIOCsParams`` / ``options: ExportOptions = {}`` in a signature.
_ANNOTATION_RE_TMPL = r"\b{name}\s*:\s*(\w+)"

#: ``searchParams.set("status", …)``
_SEARCH_PARAMS_SET_RE = re.compile(r'searchParams\.set\(\s*"([^"]+)"')

#: A frontend path literal, used to attribute a ``searchParams.set`` to the
#: endpoint built in the same function.
_PATH_LITERAL_RE = re.compile(r"`(/v1/[^`$]*)")


@lru_cache(maxsize=1)
def _interface_fields() -> dict[str, frozenset[str]]:
    """``{InterfaceName: {field names}}`` across ``frontend/src``.

    Test files are excluded: their fixture interfaces are not request shapes.
    """
    found: dict[str, frozenset[str]] = {}
    for path in sorted(_FRONTEND_SRC.rglob("*.ts")):
        if "__tests__" in path.parts or path.name.endswith(".test.ts"):
            continue
        for match in _INTERFACE_RE.finditer(path.read_text()):
            name, body = match.group(1), match.group(2)
            fields = frozenset(_FIELD_RE.findall(body))
            if fields:
                found.setdefault(name, fields)
    return found


def _normalise(path: str) -> str:
    """Frontend literal -> mounted path, with interpolations as ``{}``.

    ``client.ts`` prefixes every literal with ``/api``, and a path parameter
    reaches us as an already-stripped segment boundary.
    """
    return "/api" + re.sub(r"\{[^}]*\}", "{}", path).rstrip("/")


def _mounted_lookup() -> dict[str, frozenset[str]]:
    """Route params keyed by a path whose parameters are all ``{}``."""
    return {
        re.sub(r"\{[^}]*\}", "{}", path).rstrip("/"): params
        for path, params in _route_query_params().items()
    }


@lru_cache(maxsize=1)
def _emitted() -> tuple[tuple[Emitted, ...], int]:
    """Every ``(endpoint, param)`` the SPA sends, plus the call-site count."""
    out: list[Emitted] = []
    call_sites = 0
    interfaces = _interface_fields()

    for path in sorted(_API_CLIENT_DIR.glob("*.ts")):
        text = path.read_text()
        lines = text[: len(text)].count("\n")  # noqa: F841 - readability only

        for match in _BUILD_QUERY_RE.finditer(text):
            call_sites += 1
            endpoint = match.group("path")
            arg = match.group("arg")
            line = text[: match.start()].count("\n") + 1
            where = f"{path.name}:{line}"

            if arg.startswith("{"):
                names = set(_LITERAL_KEY_RE.findall(arg))
            else:
                # A bare identifier (possibly ``params ?? {}``). Resolve its
                # declared type from the enclosing function signature, then
                # that interface's fields.
                ident = re.match(r"(\w+)", arg)
                if not ident:
                    continue
                ann = re.search(
                    _ANNOTATION_RE_TMPL.format(name=re.escape(ident.group(1))),
                    text[: match.start()],
                )
                if not ann:
                    continue
                names = set(interfaces.get(ann.group(1), ()))

            out.extend(Emitted(endpoint, n, where) for n in sorted(names))

        # ``searchParams.set("x", …)`` attributed to the nearest following
        # ``/v1/...`` literal in the same file.
        for match in _SEARCH_PARAMS_SET_RE.finditer(text):
            following = _PATH_LITERAL_RE.search(text, match.end())
            if not following:
                continue
            line = text[: match.start()].count("\n") + 1
            out.append(Emitted(following.group(1), match.group(1), f"{path.name}:{line}"))

    return tuple(out), call_sites


# --------------------------------------------------------------------------- #
# Guard the guard
# --------------------------------------------------------------------------- #


def test_parsers_find_a_realistic_amount():
    """An empty parse would make the parity check below vacuous."""
    emitted, call_sites = _emitted()
    routes = _route_query_params()
    assert call_sites >= _MIN_CALL_SITES, f"only found {call_sites} buildQuery call sites"
    assert len(emitted) >= _MIN_PAIRS, f"only resolved {len(emitted)} (endpoint, param) pairs"
    assert routes, "no routes introspected from create_app()"


def test_the_known_regression_shape_is_visible():
    """Pin the #586 call site end to end.

    ``ExportOptions`` is the interface whose field name was wrong, reached
    through the ``buildQuery(<typed identifier>)`` form — the indirection that
    made the bug invisible. If this stops resolving, the guard has lost the
    exact shape it was written for and would pass on a repeat.
    """
    emitted, _ = _emitted()
    export_params = {e.param for e in emitted if e.endpoint == "/v1/iocs/export"}
    assert "tlp_level" in export_params, (
        "the export dialog's TLP parameter is no longer resolved through "
        f"ExportOptions; got {sorted(export_params)}"
    )
    assert "investigation_id" in export_params


# --------------------------------------------------------------------------- #
# The ratchet
# --------------------------------------------------------------------------- #


def test_every_query_param_the_spa_sends_is_declared():
    """A parameter name the route does not declare is silently discarded."""
    lookup = _mounted_lookup()
    emitted, _ = _emitted()

    problems: list[str] = []
    for item in emitted:
        mounted = _normalise(item.endpoint)
        declared = lookup.get(mounted)
        if declared is None:
            # Path resolution is test_api_reachability's job, not this one's.
            continue
        if item.param in declared:
            continue
        if f"{mounted} {item.param}" in KNOWN_GAPS:
            continue
        problems.append(
            f"  {item.source}: sends ?{item.param}= to {mounted}, "
            f"which declares {sorted(declared) or '(none)'}"
        )

    assert not problems, (
        "Query parameters the SPA sends that the route does not declare.\n"
        + "\n".join(sorted(problems))
        + "\n\nFastAPI drops these silently — no 422 — so the caller gets the "
        "route's default and the intent is lost (#586). Fix the name on "
        "whichever side is wrong, or add a KNOWN_GAPS entry describing what\n"
        "the discarded parameter breaks."
    )


def test_exemption_list_only_holds_live_entries():
    """The exemption list may only shrink."""
    lookup = _mounted_lookup()
    emitted, _ = _emitted()
    live = {f"{_normalise(e.endpoint)} {e.param}" for e in emitted}

    stale = sorted(set(KNOWN_GAPS) - live)
    assert not stale, (
        f"KNOWN_GAPS names pairs the SPA no longer sends: {stale}. "
        "Remove them — a ratchet's exemption list may only shrink."
    )

    now_declared = sorted(
        key
        for key in KNOWN_GAPS
        for mounted, param in [key.rsplit(" ", 1)]
        if param in lookup.get(mounted, frozenset())
    )
    assert not now_declared, (
        f"KNOWN_GAPS names parameters the route now declares: {now_declared}. "
        "The exemption is obsolete; delete it."
    )
