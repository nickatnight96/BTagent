"""Every production ``guard_dispatch`` site passes a classification, or is listed.

``ConnectorPolicyMiddleware``'s TLP-egress arm compares a capability's declared
``tlp_egress`` against the **active context classification**. That classification
lives in a ``ContextVar``, and ``set_active_tlp`` is called from exactly one
place in production: the agent's ``classification_hook``.

Four ``guard_dispatch`` call sites live in *backend services* — a different
process and a different context — and nothing on those paths ever sets it. So
``active_tlp`` is ``None``, ``is_tlp_allowed`` short-circuits to ``True``, and
only the HITL and undeclared-capability checks actually run. A capability
declaring ``tlp_egress=WHITE`` is dispatched for a TLP:RED investigation without
complaint (#599).

``classification_hook.py`` carries this comment from when it was wired up:

    Previously ``set_active_tlp`` was never called outside tests, so the gate
    was permanently inert (active classification stuck at None).

That was fixed *for the agent run path only*. The backend sites were added
later and inherited the original condition. The gate is not missing and not
misconfigured — it is called, it returns "allowed", and nothing anywhere
recorded that its TLP half did nothing.

**This test does not fix that**, because none of those sites currently has a
classification to pass: ``_dispatch(action_type, connector, target)`` has no
investigation in scope, the containment request body carries no
``investigation_id``, and ``DetectionProposalRow`` has neither a ``tlp_level``
column nor an investigation link. Deciding where each path's classification
comes from changes the API contract, which is a design decision rather than a
bug fix.

So this pins the gap instead, in both directions:

* a **new** dispatch site that forgets to pass ``active_tlp=`` fails here
  rather than silently joining the inert set; and
* an exemption that becomes obsolete — because someone threaded a
  classification through — also fails, so the list can only shrink.

The companion guarantee lives in ``policy.py``: an unclassified pass is now
distinguishable from a checked one (``PolicyVerdict.tlp_checked``) and logs a
warning, so the inertness is visible at runtime and not only here.
"""

from __future__ import annotations

import ast
from pathlib import Path

_GUARD = "guard_dispatch"

_ROOTS = ("agents/btagent_agents", "backend/btagent_backend", "engine/btagent_engine")

#: Sites that omit ``active_tlp=`` *legitimately*, because they run inside the
#: agent process where ``classification_hook`` has already populated the
#: run-scoped ContextVar that ``evaluate_tool_call`` falls back to.
#:
#: Keyed by ``<file stem>:<function>`` so moving a call within a file does not
#: churn the list. These are not holes — but they are not unconditional either:
#: a plugin invoked outside an investigation run has an empty ContextVar and
#: lands in the same skipped-check state, which is exactly what
#: ``PolicyVerdict.tlp_checked`` and the dispatch warning now expose.
_CONTEXTVAR_SITES: dict[str, str] = {
    "deception_hunt:run_deception_hunt_over_connector": (
        "Agent-process triage plugin — inherits the run-scoped classification "
        "set by classification_hook."
    ),
    "email_hunt:gather_email_envelopes": (
        "Agent-process triage plugin — inherits the run-scoped classification "
        "set by classification_hook."
    ),
    "ndr_hunt:run_ndr_hunt_over_connector": (
        "Agent-process triage plugin — inherits the run-scoped classification "
        "set by classification_hook."
    ),
}

#: Sites where the TLP-egress check is genuinely inert: backend-process code,
#: where nothing ever calls ``set_active_tlp``, so the ContextVar fallback
#: resolves to ``None`` and the comparison is skipped.
#:
#: Every entry is a known hole, not an approved design. The text is what has to
#: stop being true before the entry may be deleted.
_UNCLASSIFIED_SITES: dict[str, str] = {
    "containment_execute_service:_dispatch": (
        "#599 — reached from execute_response_action/execute_bulk_block, whose "
        "request bodies carry action_id but no investigation_id, so no "
        "classification is in scope. Needs the API contract decision."
    ),
    "containment_execute_service:_attach_change_record": (
        "#599 — ServiceNow change record for a bulk block. Puts the IOC value "
        "into an external ticket with the egress check skipped. Same missing "
        "investigation link as _dispatch."
    ),
    "cti_detection_service:compose_detection_pr": (
        "#599 — DetectionProposalRow has no tlp_level column and no "
        "investigation link, so the proposals being shipped carry no "
        "classification to compare against."
    ),
    "behavioral_ingest_service:rebuild_baselines_from_edr": (
        "#599 — inbound telemetry pull rather than an outbound push. Probably "
        "a genuine exemption rather than a hole, but that is the open question "
        "on the issue, so it is listed rather than quietly excluded."
    ),
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _enclosing_function(tree: ast.AST, target: ast.AST) -> str:
    """Name of the innermost function containing *target*, or ``"<module>"``."""
    best = "<module>"
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if getattr(node, "lineno", 0) <= target.lineno <= getattr(node, "end_lineno", 0):
            # Deeper (later-starting) enclosing function wins.
            best = node.name
    return best


def _scan() -> tuple[dict[str, bool], list[str]]:
    """Return ({site key: passes active_tlp}, [files scanned])."""
    sites: dict[str, bool] = {}
    scanned: list[str] = []
    root = _repo_root()
    for rel in _ROOTS:
        for path in (root / rel).rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            if _GUARD not in source:
                continue
            scanned.append(path.name)
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if name != _GUARD:
                    continue
                key = f"{path.stem}:{_enclosing_function(tree, node)}"
                passes = any(k.arg == "active_tlp" for k in node.keywords)
                # A file may hold several sites in one function; if any passes
                # a classification the others are still holes, so ``and``.
                sites[key] = sites.get(key, True) and passes
    return sites, scanned


def test_the_scanner_actually_finds_dispatch_sites():
    """Guard the guard: an empty scan would satisfy every assertion below.

    Both real assertions compare *derived sets*. If the AST walk stopped
    matching — a rename, a move to a positional call, an import alias — the
    derived set would be empty and a subset check would still pass. Pin the
    floor first.
    """
    sites, scanned = _scan()
    assert len(sites) >= 5, f"scanner found only {sorted(sites)}; it has stopped matching"
    assert "containment_execute_service.py" in scanned, (
        f"the known backend dispatch file was not scanned; saw {sorted(set(scanned))}"
    )


def test_every_site_omitting_a_classification_is_accounted_for():
    """A new dispatch site cannot silently join the inert set.

    Being *listed* is the whole requirement — in one bucket or the other. The
    two buckets differ in what they claim, and picking one is the deliberate
    act this forces: agent-process code inherits the ContextVar, backend code
    has nothing to inherit.
    """
    sites, _ = _scan()
    accounted = set(_UNCLASSIFIED_SITES) | set(_CONTEXTVAR_SITES)
    unlisted = {k for k, passes in sites.items() if not passes} - accounted
    assert not unlisted, (
        "guard_dispatch called without active_tlp= at an unlisted site: "
        f"{sorted(unlisted)}. Pass the context classification; or, if it runs "
        "in the agent process, add it to _CONTEXTVAR_SITES; or, if it is "
        "another backend hole, to _UNCLASSIFIED_SITES."
    )


def test_no_entry_outlives_its_reason():
    """Both lists only shrink. A site that starts passing must be delisted.

    Without this the lists rot into comments: entries stay after the hole is
    closed and the next reader believes there are more holes than there are.
    """
    sites, _ = _scan()
    stale = {k for k in (_UNCLASSIFIED_SITES | _CONTEXTVAR_SITES) if sites.get(k) is not False}
    assert not stale, (
        f"entries no longer describe a site that omits active_tlp=: {sorted(stale)}. "
        "Either the site now passes it (delete the entry) or it no longer "
        "exists (delete the entry)."
    )


def test_the_two_buckets_are_disjoint():
    """A site is either inheriting a classification or missing one, never both."""
    both = set(_UNCLASSIFIED_SITES) & set(_CONTEXTVAR_SITES)
    assert not both, f"listed as both inheriting and missing a classification: {sorted(both)}"


def test_every_hole_cites_the_issue():
    """A reason without a tracking reference is a shrug, not a decision."""
    for key, reason in _UNCLASSIFIED_SITES.items():
        assert "#599" in reason, f"{key} exemption does not cite the tracking issue"


def test_no_backend_site_claims_to_inherit_a_classification():
    """The ContextVar bucket is only honest for agent-process code.

    ``set_active_tlp`` is called from ``classification_hook``, which the
    backend never constructs. A backend site in ``_CONTEXTVAR_SITES`` would be
    claiming to inherit something that is always ``None`` there — the precise
    confusion that made #599 invisible.
    """
    backend = {k for k in _CONTEXTVAR_SITES if "_service" in k.split(":")[0]}
    assert not backend, (
        f"backend-process sites listed as inheriting the ContextVar: {sorted(backend)}. "
        "Nothing calls set_active_tlp in the backend; these are holes, not inheritance."
    )
