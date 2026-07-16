"""Manifest policy enforcement for the MCP router dispatch path (#100 Layer 3).

The engine enforces manifests on its integration nodes via
``ConnectorPolicyMiddleware``; this module is the same enforcement for the
agents-side MCP registry. :func:`evaluate_tool_call` is consulted by
``discovery.mcp_router_tool`` before every dispatch:

* **HITL gate** — a capability declared ``hitl_required=True`` (the
  containment actions, the detection-PR composer) is refused with a
  ``hitl_required`` verdict unless the call carries ``hitl_approved=True``.
  The flag is set by the HITL resume path after an analyst approves — the
  router envelope is what forces that round-trip; the audit trail of the
  approval lives with the HITL hook, not here.
* **TLP-egress gate** — mirrors the engine semantics: a capability's
  ``tlp_egress`` is the *highest* context classification it may run at.
  With an active classification set (see :func:`set_active_tlp`), any
  capability whose declared egress ranks below it is refused — e.g. an
  org-tenant cloud query (``AMBER_STRICT``) is blocked while the
  investigation context is ``RED``. No active classification means no TLP
  restriction (mock-first default).
* **Fail-closed for undeclared tools** — the drift test guarantees every
  registered tool has a manifest capability, so an undeclared tool name at
  runtime means a policy hole; it is refused rather than waved through.

The active classification is process-global (set per investigation by the
orchestrator's classification hook); :func:`reset_active_tlp` restores the
unrestricted default for tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from btagent_shared.types.config import TLP

from btagent_agents.mcp.manifests import MANIFESTS

# Ordering: how restrictive a classification is. A capability declared at
# rank N may run in any context of rank <= N.
TLP_RANK: dict[TLP, int] = {
    TLP.WHITE: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}

_active_tlp: TLP | None = None


def set_active_tlp(tlp: TLP | None) -> None:
    """Set the active context classification (None = unrestricted)."""
    global _active_tlp
    _active_tlp = tlp


def get_active_tlp() -> TLP | None:
    """The active context classification, or None when unrestricted."""
    return _active_tlp


def reset_active_tlp() -> None:
    """Restore the unrestricted default (test hook)."""
    set_active_tlp(None)


def is_tlp_allowed(capability_tlp: TLP, active_tlp: TLP | None) -> bool:
    """True when a capability's declared egress covers the active context."""
    if active_tlp is None:
        return True
    return TLP_RANK[capability_tlp] >= TLP_RANK[active_tlp]


@dataclass
class PolicyVerdict:
    """Outcome of a policy check for one tool call."""

    status: str  # "allowed" | "hitl_required" | "tlp_blocked" | "undeclared"
    tool_name: str
    server_id: str | None = None
    reason: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    def to_envelope(self) -> dict[str, Any]:
        """Router-shaped error envelope for a refused call."""
        return {
            "status": self.status,
            "tool_name": self.tool_name,
            "server_id": self.server_id,
            "message": self.reason,
            **self.detail,
        }


def _find_capability(tool_name: str):
    for server_id, manifest in MANIFESTS.items():
        cap = manifest.capability(tool_name)
        if cap is not None:
            return server_id, cap
    return None, None


def evaluate_tool_call(
    tool_name: str,
    *,
    active_tlp: TLP | None = None,
    hitl_approved: bool = False,
) -> PolicyVerdict:
    """Policy check for one MCP tool call (see module docstring).

    ``active_tlp`` defaults to the process-global classification set via
    :func:`set_active_tlp`; pass it explicitly to override.
    """
    if active_tlp is None:
        active_tlp = _active_tlp

    server_id, cap = _find_capability(tool_name)
    if cap is None:
        return PolicyVerdict(
            status="undeclared",
            tool_name=tool_name,
            reason=(
                f"Tool '{tool_name}' has no declared manifest capability — "
                "refusing (fail-closed). Declare it in "
                "btagent_agents.mcp.manifests before dispatching."
            ),
        )

    if not is_tlp_allowed(cap.tlp_egress, active_tlp):
        return PolicyVerdict(
            status="tlp_blocked",
            tool_name=tool_name,
            server_id=server_id,
            reason=(
                f"Capability '{tool_name}' declares tlp_egress="
                f"{cap.tlp_egress.value}, below the active context "
                f"classification {active_tlp.value} — result may not egress."
            ),
            detail={
                "capability_tlp": cap.tlp_egress.value,
                "active_tlp": active_tlp.value,
            },
        )

    if cap.hitl_required and not hitl_approved:
        return PolicyVerdict(
            status="hitl_required",
            tool_name=tool_name,
            server_id=server_id,
            reason=(
                f"'{tool_name}' is a HITL-gated action "
                f"(blast_radius={getattr(cap, 'blast_radius', None) and cap.blast_radius.value}). "
                "An analyst must approve; re-invoke with hitl_approved=true "
                "from the HITL resume path."
            ),
            detail={"requires_hitl": True},
        )

    return PolicyVerdict(status="allowed", tool_name=tool_name, server_id=server_id)
