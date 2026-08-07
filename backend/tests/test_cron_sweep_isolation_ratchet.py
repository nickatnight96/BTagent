"""Every cron sweep isolates per org, or is listed with the reason it cannot.

``scheduler.jobs._run_per_org`` commits and rolls back per tenant, so one org's
failure costs only that org's tick. It exists because of a real incident: a
single post-loop commit discarded every previously processed org's rows and
re-notified from stale state next tick.

The trap this guard exists for is that the *broken* shape looks like the fixed
one. Three sweeps carried a ``try``/``continue`` inside a single transaction
and docstrings describing themselves as "best-effort and per-org isolated".
They were not. A failure raised from a **flush** leaves the SQLAlchemy session
unusable, so every later org — and the caller's trailing commit — fails with
it. Catching an exception is not a transaction boundary, and nothing about
reading the code makes that obvious (#602, #603).

So the property is pinned mechanically instead, in both directions:

* a cron that stops calling ``_run_per_org`` fails here unless it is listed;
* an entry that no longer describes a real gap fails here too, so the list can
  only shrink.

Deliberately *not* asserted: that the listed sweeps are wrong. Both remaining
entries are honest design mismatches rather than oversights, and the reasons
say which. Forcing them through ``_run_per_org`` would be the wrong fix.
"""

from __future__ import annotations

import ast
from pathlib import Path

_PER_ORG = "_run_per_org"

#: Crons that do not isolate per org, and precisely why.
#:
#: Each value must name the obstacle, not merely assert one — an entry that
#: cannot say what has to change before it is deleted is a shrug.
_NOT_ISOLATED: dict[str, str] = {
    "taxii_feed_poll_sweep": (
        "#602 — multi-tenant, but its unit of work is the *feed*, not the org: "
        "``poll_due_feeds`` walks ``list_enabled_feeds_all_orgs`` and one org "
        "may own several feeds. Isolation here means a commit per feed, which "
        "``_run_per_org`` does not express. Needs a per-feed boundary instead."
    ),
    "stale_suppression_sweep": (
        "#602 — ``hunt_triage_service.sweep_stale_suppressions`` takes no "
        "``org_id`` and selects every ACTIVE ``SuppressionRuleRow`` across all "
        "tenants in one query. Isolating it means changing that service "
        "signature and deciding whether the sweep is genuinely org-scoped, "
        "which is a design call rather than a mechanical conversion."
    ),
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _cron_names() -> list[str]:
    """The job names registered in ``WorkerSettings.cron_jobs``.

    Read from the source rather than by importing the worker, so this stays a
    cheap static check and does not depend on arq's runtime wiring.
    """
    tree = ast.parse((_repo_root() / "backend/btagent_backend/scheduler/worker.py").read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(getattr(t, "id", "") == "cron_jobs" for t in node.targets):
            continue
        for element in node.value.elts:  # type: ignore[attr-defined]
            if isinstance(element, ast.Call) and element.args:
                name = getattr(element.args[0], "id", None)
                if name:
                    names.append(name)
    return names


def _isolation_by_job() -> dict[str, bool]:
    """{cron job name: calls ``_run_per_org``}."""
    tree = ast.parse((_repo_root() / "backend/btagent_backend/scheduler/jobs.py").read_text())
    wanted = set(_cron_names())
    found: dict[str, bool] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name not in wanted:
            continue
        calls = {
            c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", "")
            for c in ast.walk(node)
            if isinstance(c, ast.Call)
        }
        found[node.name] = _PER_ORG in calls
    return found


def test_the_scanner_finds_the_registered_crons():
    """Guard the guard: an empty scan satisfies every assertion below.

    Both real assertions compare derived sets, so a parse that stopped matching
    — ``cron_jobs`` renamed, the jobs moved to another module — would yield an
    empty mapping and still pass a subset check.
    """
    crons = _cron_names()
    assert len(crons) >= 10, f"only found {crons}; the cron_jobs parse has broken"

    resolved = _isolation_by_job()
    missing = set(crons) - set(resolved)
    assert not missing, f"registered crons with no function found in jobs.py: {sorted(missing)}"


def test_every_cron_isolates_per_org_or_is_listed():
    """A new sweep cannot quietly join the single-transaction set."""
    unlisted = {name for name, isolated in _isolation_by_job().items() if not isolated}
    unlisted -= set(_NOT_ISOLATED)
    assert not unlisted, (
        f"cron sweeps with no per-org commit boundary and no entry: {sorted(unlisted)}. "
        "Drive the walk through _run_per_org, or add the job to _NOT_ISOLATED "
        "with the specific obstacle that has to be removed first."
    )


def test_no_entry_outlives_its_reason():
    """The list only shrinks — an entry for an isolated sweep is stale."""
    isolation = _isolation_by_job()
    stale = {name for name in _NOT_ISOLATED if isolation.get(name) is not False}
    assert not stale, (
        f"_NOT_ISOLATED entries no longer describe a gap: {sorted(stale)}. "
        "Either the sweep now isolates per org, or it is no longer a cron."
    )


def test_every_entry_cites_the_issue():
    """A reason with no tracking reference cannot be followed up."""
    for name, reason in _NOT_ISOLATED.items():
        assert "#602" in reason, f"{name} entry does not cite the tracking issue"


def test_the_isolated_majority_is_actually_the_majority():
    """If this ever fails because everything is listed, the guard has inverted.

    A ratchet whose exemption list grows to cover the whole population records
    a norm nobody follows. Pinning the direction makes that a visible failure
    rather than a quiet one.
    """
    isolation = _isolation_by_job()
    isolated = sum(1 for ok in isolation.values() if ok)
    assert isolated > len(isolation) / 2, (
        f"only {isolated}/{len(isolation)} cron sweeps isolate per org — "
        "the exemption list has become the rule"
    )
