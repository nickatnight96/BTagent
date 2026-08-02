"""Manifest policy enforcement for the MCP router dispatch path (#100 Layer 3).

The engine enforces manifests on its integration nodes via
``ConnectorPolicyMiddleware``; this module is the same enforcement for the
agents-side MCP registry. :func:`evaluate_tool_call` is consulted by
``discovery.mcp_router_tool`` before every dispatch:

* **HITL gate** — a capability declared ``hitl_required=True`` (the
  containment actions, the detection-PR composer) is refused with a
  ``hitl_required`` verdict unless a server-set approval is present. The
  approval is NEVER an LLM-supplied tool argument (that would let a
  prompt-injected/misaligned agent self-approve containment, #374): it lives
  in the request/run-scoped :data:`_hitl_approved` contextvar, flipped only by
  the HITL resume path via :func:`set_hitl_approved` / :func:`hitl_approval`
  after an analyst approves. The router envelope is what forces that
  round-trip; the audit trail of the approval lives with the HITL hook.
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

The active classification is request/run-scoped, held in a
:class:`contextvars.ContextVar` and set per investigation by the classification
hook (:mod:`btagent_agents.hooks.classification_hook`). A contextvar — rather
than a process-global — is what keeps two concurrent investigations from
clobbering each other's classification (#397). :func:`reset_active_tlp`
restores the unrestricted default for tests.
"""

from __future__ import annotations

import contextvars
from collections.abc import Iterator
from contextlib import contextmanager
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

# Request/run-scoped active classification. Backed by a ContextVar so
# concurrent investigations never clobber one another — a single process-global
# would leak a TLP:RED context into an unrelated run (#397).
_active_tlp: contextvars.ContextVar[TLP | None] = contextvars.ContextVar(
    "btagent_mcp_active_tlp", default=None
)

# Request/run-scoped HITL approval. The model MUST NOT be able to set this:
# ``mcp_router_tool`` no longer exposes an ``hitl_approved`` argument (#374).
# Only the server-controlled HITL resume path flips it (via
# :func:`set_hitl_approved` / :func:`hitl_approval`) after an analyst approves a
# gated action. Defaults to False (fail-closed).
_hitl_approved: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "btagent_mcp_hitl_approved", default=False
)


def set_active_tlp(tlp: TLP | None) -> contextvars.Token[TLP | None]:
    """Set the active context classification (None = unrestricted).

    Returns the contextvar token so callers may restore the prior value; most
    callers ignore it and use :func:`reset_active_tlp`.
    """
    return _active_tlp.set(tlp)


def get_active_tlp() -> TLP | None:
    """The active context classification, or None when unrestricted."""
    return _active_tlp.get()


def reset_active_tlp() -> None:
    """Restore the unrestricted default (test hook)."""
    _active_tlp.set(None)


@contextmanager
def active_tlp_scope(tlp: TLP | None) -> Iterator[None]:
    """Scope the active classification to a block, restoring the prior value."""
    token = _active_tlp.set(tlp)
    try:
        yield
    finally:
        _active_tlp.reset(token)


def set_hitl_approved(approved: bool) -> contextvars.Token[bool]:
    """Server-only: mark the current run/request context as HITL-approved.

    Called EXCLUSIVELY by the HITL resume path after an analyst approves a
    gated action — never from an LLM-supplied tool argument (#374). Returns the
    contextvar token so callers may restore the prior value.
    """
    return _hitl_approved.set(approved)


def is_hitl_approved() -> bool:
    """Whether the current context carries a server-set HITL approval."""
    return _hitl_approved.get()


def reset_hitl_approved() -> None:
    """Clear any server-set HITL approval (fail-closed default)."""
    _hitl_approved.set(False)


@contextmanager
def hitl_approval(approved: bool = True) -> Iterator[None]:
    """Scope a server-set HITL approval to the approved re-invocation block.

    The HITL resume path wraps its re-dispatch of an analyst-approved action in
    this context manager so the router's HITL gate sees the approval without
    ever exposing it to the model.
    """
    token = _hitl_approved.set(approved)
    try:
        yield
    finally:
        _hitl_approved.reset(token)


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


class MCPPolicyRefused(RuntimeError):
    """A manifest policy verdict refused this dispatch (A3).

    Raised by :func:`guard_dispatch` so *direct* dispatch sites — the backend
    services that import MCP server classes and call their tools without going
    through ``mcp_router_tool`` — enforce the same manifest policy the router
    path does. Callers that need the structured verdict (e.g. to write an
    audited denial) read ``.verdict``.
    """

    def __init__(self, verdict: PolicyVerdict) -> None:
        super().__init__(verdict.reason)
        self.verdict = verdict


def guard_dispatch(
    tool_name: str,
    *,
    active_tlp: TLP | None = None,
    hitl_approved: bool | None = None,
) -> PolicyVerdict:
    """Enforce the manifest policy at a direct dispatch site, or raise.

    A3: production dispatch imports MCP server classes directly, so the
    router-only :func:`evaluate_tool_call` gate never ran — TLP-egress and
    HITL declarations in ``manifests.py`` were documentation. Every direct
    call site invokes this immediately before calling the server method.

    ``hitl_approved`` is server-side state only: pass ``True`` exactly when
    the call site sits *behind* its own human approval chain (containment's
    approve→execute double-gate, the detection-PR ship endpoint that follows
    per-proposal analyst acceptance). It must never be derived from model
    output (#374).
    """
    verdict = evaluate_tool_call(tool_name, active_tlp=active_tlp, hitl_approved=hitl_approved)
    if not verdict.allowed:
        raise MCPPolicyRefused(verdict)
    return verdict


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
    hitl_approved: bool | None = None,
) -> PolicyVerdict:
    """Policy check for one MCP tool call (see module docstring).

    ``active_tlp`` defaults to the run-scoped classification set via
    :func:`set_active_tlp`; pass it explicitly to override.

    ``hitl_approved`` defaults to the run-scoped, server-only approval set via
    :func:`set_hitl_approved` — it is deliberately NOT sourced from any
    LLM-supplied argument (#374). Pass it explicitly only from server-side
    callers/tests that model the resume path.
    """
    if active_tlp is None:
        active_tlp = _active_tlp.get()
    if hitl_approved is None:
        hitl_approved = _hitl_approved.get()

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
