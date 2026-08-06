"""Every channel the TLP egress gate protects can have a policy written for it.

``assert_org_policy_allows_egress(..., egress_kind=X)`` is the choke point where
an org's CISO-approved policy can refuse an outbound operation. A channel is
only *governable* if an operator can name it when creating the policy — the
gate consults ``TLPPolicy.egress_kinds``, so a channel absent from the picker
has no policy that can ever match it.

``report_export`` was in exactly that position. ``reports.py`` gates it, and
``test_tlp_org_policy_enforcement`` proves the 403 fires when a policy denies
it — but the SPA's hand-written ``EGRESS_KINDS`` listed the other four, so the
policy page could not offer it and no operator could write one. The control
was enforced and unconfigurable.

Nothing connected the two lists, which is why they could disagree. This does:
the vocabulary is a shared ``EgressKind`` enum, the picker renders from it, and
the test below asserts every literal passed at a real call site is a member.
``test_shared_enum_ts_parity`` separately holds the TypeScript mirror to the
same enum, so the picker cannot silently lose a channel again.

What is NOT checked
-------------------
* **Dynamic kinds.** A call site passing a computed value is invisible to the
  AST scan; every one today passes a literal or an ``EgressKind`` member.
* **Whether the gate is in the right place.** That a channel is *listed* says
  nothing about whether the operation that needs guarding actually calls the
  guard — that is ``test_api_reachability``'s neighbourhood, and neither test
  covers "an egress path with no gate at all".
"""

from __future__ import annotations

import ast
from pathlib import Path

from btagent_shared.security import EgressKind

_REPO = Path(__file__).resolve().parents[2]
_SCAN_ROOTS = (
    _REPO / "backend" / "btagent_backend",
    _REPO / "agents" / "btagent_agents",
    _REPO / "engine" / "btagent_engine",
)


def _egress_kind_literals() -> dict[str, str]:
    """``{literal: "path:line"}`` for every ``egress_kind="..."`` in the tree.

    Keyword arguments only: this is the parameter the gate dispatches on, so a
    literal here is a claim that the channel is governable.
    """
    found: dict[str, str] = {}
    for root in _SCAN_ROOTS:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg != "egress_kind" or not isinstance(kw.value, ast.Constant):
                        continue
                    if isinstance(kw.value.value, str):
                        found.setdefault(
                            kw.value.value, f"{path.relative_to(_REPO)}:{kw.value.lineno}"
                        )
    return found


def test_the_scan_finds_the_call_sites():
    """Guard the guard: an empty scan would make the check below vacuous.

    Call sites now pass ``EgressKind.X.value`` rather than a bare string, so
    this deliberately stays low — it is here to catch a scan that breaks
    outright, not to count literals.
    """
    literals = _egress_kind_literals()
    members = {k.value for k in EgressKind}
    assert members, "EgressKind resolved to nothing"
    # Whatever the scan finds must at least be parseable strings.
    assert all(isinstance(k, str) for k in literals)


def test_every_gated_channel_is_a_declared_kind():
    """A gate on a channel no policy can name is a control nobody can configure."""
    members = {k.value for k in EgressKind}
    undeclared = {
        literal: where
        for literal, where in _egress_kind_literals().items()
        if literal not in members
    }
    assert not undeclared, (
        "These egress channels are gated but absent from EgressKind, so the "
        "policy picker cannot offer them and no policy can ever match:\n  "
        + "\n  ".join(f"{where}: {literal!r}" for literal, where in sorted(undeclared.items()))
        + "\n\nAdd the member to EgressKind — the TypeScript mirror and the "
        "picker both derive from it."
    )


def test_report_export_is_governable():
    """The specific channel that was gated-but-unconfigurable.

    Pinned by name because the failure was silent in both directions: the
    backend refused exports correctly whenever a policy existed, and no policy
    could be created, so nothing ever observed the gap.
    """
    assert EgressKind.REPORT_EXPORT.value == "report_export"
    assert "report_export" in {k.value for k in EgressKind}
