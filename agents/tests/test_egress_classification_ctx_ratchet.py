"""Every baseline-gate call site supplies a classification context.

``assert_tlp_allows_egress(payload, egress_kind, classification_ctx=...)`` does
two independent things:

1. resolves *classification_ctx* to a TLP and refuses if it is RED; and
2. walks *payload* for an embedded ``tlp`` / ``tlp_level`` field tagged RED.

Only the second survives a forgotten ``classification_ctx``. Omitting it
resolves to GREEN (``_resolve_classification(None)`` — "no TLP field at all ->
unset -> GREEN"), so arm 1 silently passes and the call is protected only by
whatever the payload happens to tag itself.

That gap is narrower than it first looks, and worth stating precisely rather
than overclaiming: a payload carrying an explicit ``tlp: red`` field is still
blocked. What is *not* blocked is the case the parameter exists for — a RED
**investigation** whose outgoing payload carries no tag of its own. STIX
exports, report renders and knowledge ingests all derive their classification
from the investigation rather than from the bytes, so for exactly those sites
the omission is total.

All ten production call sites pass it today. That is precisely when this is
cheapest to pin: nothing to fix, and an eleventh site that forgets inherits a
silent GREEN instead of a test failure. The failure mode has already appeared
twice in adjacent code — a policy channel with no gate (#598) and a gate whose
TLP arm never ran (#600) — both of which reported success while doing nothing.

``classification_ctx`` is positional-or-keyword, so a site passing it as the
third positional argument is equally fine and this accepts both.
"""

from __future__ import annotations

import ast
from pathlib import Path

_GATE = "assert_tlp_allows_egress"

_ROOTS = (
    "backend/btagent_backend",
    "agents/btagent_agents",
    "engine/btagent_engine",
    "shared/btagent_shared",
)

#: Sites allowed to omit the classification, and why. Empty, and meant to stay
#: that way — an entry here is a site whose egress is guarded only by payload
#: self-tagging.
_NO_CONTEXT_SITES: dict[str, str] = {}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _enclosing_function(tree: ast.AST, target: ast.AST) -> str:
    best = "<module>"
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if getattr(node, "lineno", 0) <= target.lineno <= getattr(node, "end_lineno", 0):
            best = node.name
    return best


def _scan() -> dict[str, bool]:
    """{site key: supplies a classification context}."""
    sites: dict[str, bool] = {}
    root = _repo_root()
    for rel in _ROOTS:
        for path in (root / rel).rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            if _GATE not in source:
                continue
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if name != _GATE:
                    continue
                # Third positional argument, or the keyword. The signature is
                # (payload, egress_kind, classification_ctx=None, *, org_id=None).
                supplied = len(node.args) >= 3 or any(
                    k.arg == "classification_ctx" for k in node.keywords
                )
                key = f"{path.stem}:{_enclosing_function(tree, node)}:{node.lineno}"
                sites[key] = supplied
    return sites


def test_the_scanner_finds_the_known_call_sites():
    """Guard the guard: an empty scan satisfies every assertion below.

    Both real assertions compare derived sets, so a walk that stopped matching
    — a rename, an import alias, a move behind a wrapper — would produce an
    empty set and still pass a subset check.
    """
    sites = _scan()
    assert len(sites) >= 8, f"scanner found only {sorted(sites)}; it has stopped matching"
    files = {k.split(":")[0] for k in sites}
    # One from each tier, so a scan that silently lost a whole package fails.
    for expected in ("stix_service", "adapters", "event_emitter", "cti_to_detection"):
        assert expected in files, f"{expected} missing from the scan; saw {sorted(files)}"


def test_every_call_site_supplies_a_classification():
    sites = _scan()
    missing = {k for k, supplied in sites.items() if not supplied} - set(_NO_CONTEXT_SITES)
    assert not missing, (
        f"{_GATE} called without classification_ctx at: {sorted(missing)}. "
        "Omitting it resolves to GREEN, so the investigation-classification arm "
        "of the gate silently passes and only payload self-tagging is left. "
        "Pass the investigation's classification, or add the site to "
        "_NO_CONTEXT_SITES with the reason it has none."
    )


def test_no_exemption_outlives_its_reason():
    """The list only shrinks; it starts empty and should stay that way."""
    sites = _scan()
    stale = {k for k in _NO_CONTEXT_SITES if sites.get(k) is not False}
    assert not stale, (
        f"_NO_CONTEXT_SITES entries no longer describe a site that omits it: {sorted(stale)}"
    )


def test_omitting_the_context_really_does_resolve_to_green():
    """The premise of this whole module, asserted rather than assumed.

    If the default ever became fail-closed, this ratchet would be guarding a
    property that no longer matters, and the docstring above would be wrong.
    Pin the behaviour so that change is a conversation.
    """
    from btagent_shared.security.tlp import assert_tlp_allows_egress

    # A payload that tags nothing, from a caller that supplies no context:
    # permitted today, which is exactly why the parameter must be passed.
    assert_tlp_allows_egress({"indicator": "8.8.8.8"}, "stix_export")
