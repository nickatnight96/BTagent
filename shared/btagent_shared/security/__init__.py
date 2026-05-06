"""Shared security primitives — exceptions, TLP egress gate, classification helpers.

Lives in ``btagent_shared`` so both ``btagent_agents`` (hooks, MCP) and
``btagent_backend`` (STIX export, knowledge ingest) can call the same
gate without crossing package boundaries.
"""

from __future__ import annotations

from btagent_shared.security.tlp import (
    EgressKind,
    TLPViolation,
    assert_tlp_allows_egress,
)

__all__ = [
    "EgressKind",
    "TLPViolation",
    "assert_tlp_allows_egress",
]
