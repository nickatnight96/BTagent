"""The declared set of policy-enforced egress channels matches the call sites.

``EgressKind`` (#597) names five channels an org's TLP policy may govern. Only
three of them have an ``assert_org_policy_allows_egress`` call site:

    stix_export      iocs.py        enforced
    report_export    reports.py     enforced
    knowledge_ingest knowledge.py   enforced
    mcp_return       —              advisory
    event_emit       —              advisory

The two without a call site are not merely undone: they were *indistinguishable
from the other three* at every surface an operator touches. The picker offered
them, ``POST /tlp-policies/evaluate`` answered for them with the same
``allowed: false``, and the SPA rendered the same red BLOCKED badge — while a
connector return or an emitted event carrying that classification left anyway.
A CISO could deny ``mcp_return`` of AMBER_STRICT, watch the product agree, and
have configured nothing.

That is the same family as #596 and #597 and one rung further out again. There
the missing thing was a *value* — absent from a request vocabulary (#596), then
from a policy vocabulary (#597). Here the value is present everywhere it should
be and the *enforcement point* is missing, which no vocabulary check can see:
the channel is named, accepted, stored and evaluated. Only the gate is absent.

The fix is not to pretend the gap is closed — enforcing ``event_emit`` means a
DB lookup on the WS fan-out hot path and ``mcp_return`` lives in a process with
no backend session (see ``POLICY_ENFORCED_EGRESS_KINDS`` for the detail). It is
to make the gap *declared*, and this is the test that keeps the declaration
honest. It derives the enforced set from the actual call sites and compares it
to the constant **in both directions**, so:

* wiring up a new gate without moving the channel into the constant fails, and
* deleting a gate while the constant still claims it fails.

A one-directional check would let the constant drift into a comment that
happens to be true today.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from btagent_shared.security.tlp import _VALID_EGRESS_KINDS as TLP_MODULE_KINDS
from btagent_shared.security.tlp import EgressKind as EgressKindLiteral
from btagent_shared.security.tlp_policy import (
    POLICY_ENFORCED_EGRESS_KINDS,
    EgressKind,
    advisory_egress_kinds,
    is_policy_enforced,
)

_GUARD = "assert_org_policy_allows_egress"

# Packages that may contain a real call site. Tests are excluded deliberately:
# `test_tlp_org_policy_enforcement` calls the guard directly with several
# kinds, and counting those would report every channel as enforced — the
# scanner would then agree with any constant at all.
_ROOTS = ("backend/btagent_backend", "agents/btagent_agents", "engine/btagent_engine")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _python_files() -> list[Path]:
    root = _repo_root()
    return [p for r in _ROOTS for p in (root / r).rglob("*.py")]


def _kind_of(node: ast.keyword) -> str | None:
    """Resolve an ``egress_kind=`` argument to its wire value, or None.

    Handles the two forms in the tree: a bare literal (``"stix_export"``) and
    an enum member (``EgressKind.STIX_EXPORT`` / ``.value``). Anything computed
    returns None and is reported separately — a call site whose channel this
    cannot read is a hole in the scan, not a passing case.
    """
    value = node.value
    if isinstance(value, ast.Attribute) and value.attr == "value":
        value = value.value
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
        if value.value.id == "EgressKind":
            member = getattr(EgressKind, value.attr, None)
            return member.value if member is not None else None
    return None


def _scan_call_sites() -> tuple[set[str], list[str]]:
    """Return (channels passed to the guard, unresolvable call-site locations)."""
    found: set[str] = set()
    unresolved: list[str] = []
    for path in _python_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - would fail the lint job first
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name != _GUARD:
                continue
            kw = next((k for k in node.keywords if k.arg == "egress_kind"), None)
            if kw is None:
                unresolved.append(f"{path.name}:{node.lineno} (no egress_kind= keyword)")
                continue
            kind = _kind_of(kw)
            if kind is None:
                unresolved.append(f"{path.name}:{node.lineno} (computed egress_kind)")
            else:
                found.add(kind)
    return found, unresolved


def test_the_scanner_finds_the_known_call_sites():
    """Guard the guard: a scanner that finds nothing agrees with everything.

    Every assertion below is about a *set derived from this scan*. If the AST
    walk silently stopped matching — a rename, a decorator, a move to a
    positional argument — the derived set would be empty and would still
    satisfy a subset check. So pin the floor first, and pin it to the count of
    real gates rather than to a specific file, which is what the assertions
    that follow are for.
    """
    found, unresolved = _scan_call_sites()
    assert not unresolved, f"call sites whose channel could not be resolved: {unresolved}"
    assert len(found) >= 3, f"scanner found only {found}; it has stopped matching call sites"


def test_declared_enforced_set_matches_the_call_sites_exactly():
    """Both directions. A gate without a declaration, or the reverse, fails."""
    found, _ = _scan_call_sites()
    declared = {k.value for k in POLICY_ENFORCED_EGRESS_KINDS}
    assert found == declared, (
        "POLICY_ENFORCED_EGRESS_KINDS disagrees with the tree. "
        f"gated but not declared: {sorted(found - declared)}; "
        f"declared but not gated: {sorted(declared - found)}"
    )


def test_every_declared_channel_is_a_real_egress_kind():
    """The constant is typed as EgressKind; this catches a raw-string slip."""
    assert POLICY_ENFORCED_EGRESS_KINDS <= set(EgressKind)


def test_the_advisory_channels_are_the_rest_and_are_not_empty():
    """If this ever fails because the set is empty, delete this module.

    An empty advisory set means every channel is enforced, at which point the
    whole distinction — and the ``policy_enforced`` flag on the API — is dead
    weight rather than a warning. That is a good failure to be forced to read.
    """
    advisory = set(EgressKind) - POLICY_ENFORCED_EGRESS_KINDS
    assert advisory == {EgressKind.MCP_RETURN, EgressKind.EVENT_EMIT}


@pytest.mark.parametrize("kind", list(EgressKind))
def test_is_policy_enforced_accepts_the_wire_string_and_the_member(kind: EgressKind):
    """The API receives a raw string; the call sites hold members.

    ``EgressKind`` is a ``StrEnum``, so both must give the same answer — a
    containment check that silently disagreed for one form would mislabel
    exactly the surface this exists to label.
    """
    assert is_policy_enforced(kind) is is_policy_enforced(kind.value)


def test_empty_channel_selection_counts_as_covering_the_advisory_ones():
    """Empty ``egress_kinds`` means "any channel" in ``TLPPolicy.matches``.

    Reporting the broadest possible policy as having no advisory channels
    would invert the warning precisely where it matters most.
    """
    assert advisory_egress_kinds([]) == (EgressKind.MCP_RETURN, EgressKind.EVENT_EMIT)
    assert advisory_egress_kinds(None) == (EgressKind.MCP_RETURN, EgressKind.EVENT_EMIT)


def test_an_all_enforced_selection_has_nothing_advisory():
    assert advisory_egress_kinds(["stix_export", "report_export"]) == ()


def test_advisory_kinds_are_returned_in_declaration_order():
    """Set ordering would make audit records and API responses non-deterministic."""
    assert advisory_egress_kinds(["event_emit", "mcp_return"]) == (
        EgressKind.MCP_RETURN,
        EgressKind.EVENT_EMIT,
    )


def test_the_two_egress_kind_vocabularies_agree():
    """``tlp.py`` keeps its own copy; it must not drift from the enum.

    ``btagent_shared.security.tlp`` deliberately carries no import-time
    dependency on the policy module (it imports the event type lazily inside
    ``_emit_block_event``), so it declares the channel list a second time as a
    ``Literal`` plus a frozenset. That constraint is worth keeping, but two
    hand-written copies of one vocabulary is the exact shape of the bug #597
    fixed — so tie them together here instead of trusting them to stay level.
    """
    enum_values = {k.value for k in EgressKind}
    assert set(EgressKindLiteral.__args__) == enum_values  # type: ignore[attr-defined]
    assert TLP_MODULE_KINDS == enum_values
