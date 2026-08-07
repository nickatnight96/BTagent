"""An "allowed" verdict says whether the TLP-egress check actually ran.

Before this, ``PolicyVerdict(status="allowed")`` meant one of two very
different things:

* the capability's declared ``tlp_egress`` covers the active context
  classification — the gate ran and permitted the call; or
* no classification was supplied, so ``is_tlp_allowed`` short-circuited to
  ``True`` and the comparison never happened.

Nothing distinguished them — not the verdict, not the envelope, not a log
line. Every backend ``guard_dispatch`` site is in the second state (#599), so
the egress arm of the connector gate has been inert there since it was added,
reporting success the whole time.

These tests pin the distinction, and pin that a caller can opt into refusing
the second case outright.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.config import TLP

from btagent_agents.mcp.policy import (
    MCPPolicyRefused,
    active_tlp_scope,
    evaluate_tool_call,
    guard_dispatch,
    reset_active_tlp,
)

# A declared, non-HITL capability, so the only variable is the classification.
_TOOL = "snow_create_security_incident"


@pytest.fixture(autouse=True)
def _clear_classification():
    """The active TLP is a ContextVar; a leaked value would flip these silently."""
    reset_active_tlp()
    yield
    reset_active_tlp()


def test_a_checked_pass_is_marked_checked():
    with active_tlp_scope(TLP.WHITE):
        verdict = evaluate_tool_call(_TOOL)
    assert verdict.allowed
    assert verdict.tlp_checked is True
    assert verdict.unclassified_pass is False


def test_an_unclassified_pass_is_marked_unchecked():
    """Same status, same `allowed`, different meaning — that was the bug."""
    verdict = evaluate_tool_call(_TOOL)
    assert verdict.allowed
    assert verdict.status == "allowed"  # indistinguishable on status alone...
    assert verdict.tlp_checked is False  # ...and distinguishable only here
    assert verdict.unclassified_pass is True


def test_the_allowed_verdict_carries_what_it_would_have_compared_against():
    """Without this the reader cannot tell what the skipped check would have done."""
    verdict = evaluate_tool_call(_TOOL)
    assert verdict.detail["capability_tlp"]


def test_guard_dispatch_warns_when_the_check_is_skipped(caplog):
    """The only runtime trace that the egress arm did nothing."""
    with caplog.at_level(logging.WARNING, logger="btagent.mcp.policy"):
        guard_dispatch(_TOOL)
    messages = [r.getMessage() for r in caplog.records]
    assert any("no active classification" in m for m in messages), (
        f"expected a skipped-check warning, got {messages}"
    )
    # The capability's declared level has to be in the line: "the check was
    # skipped" is only actionable alongside what it would have compared to.
    assert any("tlp_egress=" in m for m in messages), messages


def test_guard_dispatch_is_quiet_when_the_check_ran(caplog):
    """A warning on every checked dispatch would train operators to ignore it."""
    with caplog.at_level(logging.WARNING, logger="btagent.mcp.policy"):
        with active_tlp_scope(TLP.WHITE):
            guard_dispatch(_TOOL)
    assert not [r for r in caplog.records if "no active classification" in r.getMessage()]


def test_require_classification_refuses_rather_than_skipping():
    with pytest.raises(MCPPolicyRefused) as excinfo:
        guard_dispatch(_TOOL, require_classification=True)
    verdict = excinfo.value.verdict
    assert verdict.status == "unclassified"
    assert verdict.tlp_checked is False
    assert not verdict.allowed


def test_require_classification_permits_a_classified_dispatch():
    """Guard the guard: the opt-in must refuse *the missing classification*.

    A `require_classification` that refused unconditionally would pass the
    test above while being useless, so pin that supplying one lets the call
    through.
    """
    with active_tlp_scope(TLP.WHITE):
        verdict = guard_dispatch(_TOOL, require_classification=True)
    assert verdict.allowed
    assert verdict.tlp_checked is True


def test_an_explicit_classification_beats_an_empty_contextvar():
    """The fix for #599 will pass `active_tlp=` from the backend, not set the var."""
    verdict = evaluate_tool_call(_TOOL, active_tlp=TLP.WHITE)
    assert verdict.tlp_checked is True


def test_a_blocked_capability_still_blocks_and_is_marked_checked():
    """The new flag must not soften the refusal path it sits next to."""
    verdict = evaluate_tool_call(_TOOL, active_tlp=TLP.RED)
    assert not verdict.allowed
    assert verdict.status == "tlp_blocked"
