"""Shared security primitives — exceptions, TLP egress gate, classification helpers.

Lives in ``btagent_shared`` so both ``btagent_agents`` (hooks, MCP) and
``btagent_backend`` (STIX export, knowledge ingest) can call the same
gate without crossing package boundaries.
"""

from __future__ import annotations

from btagent_shared.security.ocsf_map import OCSF_MAPS, OCSFFieldMap, get_map
from btagent_shared.security.safelist import (
    BASELINE_SAFELIST,
    SafelistPolicy,
    domain_from_url,
    is_structurally_reserved_ip,
)
from btagent_shared.security.tlp import (
    TLPViolation,
    assert_tlp_allows_egress,
)
from btagent_shared.security.tlp_policy import (
    POLICY_ENFORCED_EGRESS_KINDS,
    EgressKind,
    PolicyDecision,
    TLPPolicy,
    TLPPolicyAction,
    TLPViolationEvent,
    ViolationSink,
    advisory_egress_kinds,
    clear_violation_sink,
    emit_violation,
    evaluate_egress_policy,
    get_violation_sink,
    is_policy_enforced,
    set_violation_sink,
    tlp_rank,
)

__all__ = [
    "BASELINE_SAFELIST",
    "POLICY_ENFORCED_EGRESS_KINDS",
    "EgressKind",
    "OCSF_MAPS",
    "OCSFFieldMap",
    "PolicyDecision",
    "SafelistPolicy",
    "TLPPolicy",
    "TLPPolicyAction",
    "TLPViolation",
    "TLPViolationEvent",
    "ViolationSink",
    "advisory_egress_kinds",
    "assert_tlp_allows_egress",
    "clear_violation_sink",
    "domain_from_url",
    "emit_violation",
    "evaluate_egress_policy",
    "get_map",
    "is_policy_enforced",
    "is_structurally_reserved_ip",
    "get_violation_sink",
    "set_violation_sink",
    "tlp_rank",
]
