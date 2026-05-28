"""Shared security primitives — exceptions, TLP egress gate, classification helpers.

Lives in ``btagent_shared`` so both ``btagent_agents`` (hooks, MCP) and
``btagent_backend`` (STIX export, knowledge ingest) can call the same
gate without crossing package boundaries.
"""

from __future__ import annotations

from btagent_shared.security.ocsf_map import OCSF_MAPS, OCSFFieldMap, get_map
from btagent_shared.security.tlp import (
    EgressKind,
    TLPViolation,
    assert_tlp_allows_egress,
)
from btagent_shared.security.tlp_policy import (
    PolicyDecision,
    TLPPolicy,
    TLPPolicyAction,
    TLPViolationEvent,
    ViolationSink,
    clear_violation_sink,
    emit_violation,
    evaluate_egress_policy,
    get_violation_sink,
    set_violation_sink,
    tlp_rank,
)

__all__ = [
    "EgressKind",
    "OCSF_MAPS",
    "OCSFFieldMap",
    "PolicyDecision",
    "TLPPolicy",
    "TLPPolicyAction",
    "TLPViolation",
    "TLPViolationEvent",
    "ViolationSink",
    "assert_tlp_allows_egress",
    "clear_violation_sink",
    "emit_violation",
    "evaluate_egress_policy",
    "get_map",
    "get_violation_sink",
    "set_violation_sink",
    "tlp_rank",
]
