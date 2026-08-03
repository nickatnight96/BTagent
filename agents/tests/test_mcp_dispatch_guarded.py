"""Every direct MCP dispatch site is policy-gated, or exempt on the record (A3).

Production code imports MCP server classes directly and calls their methods,
so the router-only :func:`evaluate_tool_call` gate never runs on the real path
— which is what made the TLP-egress and HITL declarations in ``manifests.py``
documentation rather than enforcement. P3.2 fixed that by calling
:func:`guard_dispatch` at each direct call site.

Which sites those *are* was established by reading the tree once. That answer
rots: the next module that imports a server class inherits none of the
reasoning, and nothing fails. This is the ratchet that keeps it true — the
same shape as the API-reachability guard and the manifest drift-lock.

The rule: a module that imports from ``btagent_agents.mcp.servers`` either
calls ``guard_dispatch`` itself, or appears in :data:`GATED_ELSEWHERE` with
the reason it doesn't have to. Adding a line to that map is a deliberate
claim someone can check, which is the point — a silent omission is not.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Trees whose modules may dispatch to connectors. The ``mcp`` package itself is
# excluded: it *is* the registry/policy layer (servers importing each other and
# ``policy.py`` importing servers are not dispatch sites).
_SEARCH_ROOTS = (
    _REPO_ROOT / "backend" / "btagent_backend",
    _REPO_ROOT / "agents" / "btagent_agents",
    _REPO_ROOT / "engine" / "btagent_engine",
)
_EXCLUDED_DIR = _REPO_ROOT / "agents" / "btagent_agents" / "mcp"

_IMPORTS_A_SERVER = re.compile(r"^\s*(?:from|import)\s+btagent_agents\.mcp\.servers", re.M)
_CALLS_THE_GUARD = re.compile(r"\bguard_dispatch\s*\(")

# Modules that import a server class but legitimately do not call the guard
# themselves. Each entry states WHERE the gate actually runs — an exemption
# without a checkable reason is just a silenced test.
GATED_ELSEWHERE: dict[str, str] = {
    # These three construct the connector and hand it straight to the
    # agents-side hunt plugin, which calls guard_dispatch immediately before
    # the server method. Guarding here too would double-gate one dispatch.
    "backend/btagent_backend/services/deception_hunt_run_service.py": (
        "delegates to plugins.triage.deception_hunt, which guards canary_list_incidents"
    ),
    "backend/btagent_backend/services/email_hunt_run_service.py": (
        "delegates to plugins.triage.email_hunt, which guards each provider method"
    ),
    "backend/btagent_backend/services/ndr_hunt_run_service.py": (
        "delegates to plugins.triage.ndr_hunt, which guards vectra_list_detections"
    ),
    # Emulation is gated by a *different*, stronger control: run() calls
    # require_sandbox(target_env) before the trigger, so a non-sandbox target
    # is refused before any emulator method runs, and the default trigger
    # pins mock_mode=True regardless of the fleet-wide switch. The manifest
    # gate is still the missing half of defence-in-depth here; wiring it needs
    # a decision about how emulation approval is represented, which belongs to
    # the #118 live-ART sign-off. ``test_art_trigger_stays_mock_pinned`` below
    # fails the moment that pin is lifted without the gate arriving.
    "agents/btagent_agents/validation/orchestrator.py": (
        "sandbox-gated (require_sandbox precedes trigger) + mock-pinned; "
        "manifest gate tracked under #118 live-ART sign-off"
    ),
}


def _dispatch_site_modules() -> dict[str, str]:
    """``{repo-relative path: source}`` for every module importing a server."""
    found: dict[str, str] = {}
    for root in _SEARCH_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if _EXCLUDED_DIR in path.parents or path == _EXCLUDED_DIR:
                continue
            src = path.read_text(encoding="utf-8")
            if _IMPORTS_A_SERVER.search(src):
                found[str(path.relative_to(_REPO_ROOT))] = src
    return found


def test_extraction_actually_finds_dispatch_sites():
    """Guard the guard: a broken matcher would pass everything silently."""
    sites = _dispatch_site_modules()
    assert len(sites) >= 5, f"only found {len(sites)} dispatch sites; matcher broken?"
    assert "backend/btagent_backend/services/containment_execute_service.py" in sites


def test_every_direct_dispatch_site_is_guarded_or_declared():
    ungated = sorted(
        rel
        for rel, src in _dispatch_site_modules().items()
        if not _CALLS_THE_GUARD.search(src) and rel not in GATED_ELSEWHERE
    )
    assert not ungated, (
        "These modules dispatch to an MCP server without calling guard_dispatch, "
        "so the TLP-egress and HITL policy their manifest declares is not "
        "enforced on this path (A3):\n  " + "\n  ".join(ungated) + "\n\n"
        "Either call guard_dispatch(tool_name, ...) immediately before the "
        "server method, or add the module to GATED_ELSEWHERE with the reason "
        "the gate runs somewhere else."
    )


def test_exemptions_still_describe_real_dispatch_sites():
    """A stale exemption is dead weight — and hides the next real one."""
    sites = _dispatch_site_modules()
    stale = sorted(rel for rel in GATED_ELSEWHERE if rel not in sites)
    assert not stale, (
        "These are exempted but no longer import an MCP server:\n  "
        + "\n  ".join(stale)
        + "\n\nDelete them — the list only shrinks."
    )


def test_exemptions_that_started_guarding_themselves_are_removed():
    """If an exempt module grew its own guard, the exemption is a lie."""
    now_guarded = sorted(
        rel
        for rel, src in _dispatch_site_modules().items()
        if rel in GATED_ELSEWHERE and _CALLS_THE_GUARD.search(src)
    )
    assert not now_guarded, (
        "These call guard_dispatch now, so their GATED_ELSEWHERE entry is "
        "stale:\n  " + "\n  ".join(now_guarded)
    )


def test_art_trigger_stays_mock_pinned():
    """The exemption above rests on this: emulation cannot go live by env flip.

    ``_default_trigger`` constructs the ART server with ``mock_mode=True``
    explicitly, so flipping the fleet-wide ``BTAGENT_MOCK_CONNECTORS`` switch
    cannot turn the validation loop into a live emulator. If that pin is ever
    removed, this fails — and the manifest gate has to arrive with it.
    """
    src = (_REPO_ROOT / "agents" / "btagent_agents" / "validation" / "orchestrator.py").read_text(
        encoding="utf-8"
    )
    assert "AtomicRedTeamMCPServer(mock_mode=True)" in src, (
        "The validation orchestrator no longer pins the ART server to mock mode. "
        "That pin is what makes the GATED_ELSEWHERE exemption safe — going live "
        "requires guard_dispatch('run_atomic', hitl_approved=...) at the "
        "dispatch site first (#118)."
    )


def test_run_atomic_is_declared_hitl_required():
    """Pins the premise: emulation is an approval-gated action, like containment."""
    from btagent_agents.mcp.manifests import get_manifest

    manifest = get_manifest("atomic_red_team")
    run_atomic = next(c for c in manifest.actions if c.id == "run_atomic")
    assert run_atomic.hitl_required is True
