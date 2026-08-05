"""Containment execute-and-record service (EPIC-3 #106 — approve→execute→record).

This is the *only* place in BTagent where an approved containment / mitigation
action is actually dispatched through the connector/MCP layer. It exists so the
proposal-only planning surfaces (``/response-plan``, ``/mitigation``) gain a
guarded execution path.

SAFETY (this module is the enforcement point for #106's non-negotiables):

1. **Double-gated.** The route requires the ``containment:execute`` RBAC scope
   *and* an explicit prior approval (``approved=True``); this service refuses to
   run anything not marked approved.
2. **Mock by default.** Dispatch honours ``BTAGENT_MOCK_CONNECTORS`` (default
   on). Live connectors stay behind their existing ``NotImplementedError``
   guards — this module never unbolts them and raises its own guard for any
   action with no mock path. Tests never perform real egress.
3. **Safelist first.** For any block — and, since #117, any cloud IAM
   control-plane action (revoke role / freeze access key / detach policy) — the
   org safelist is consulted *before* any dispatch. A safelisted target is
   refused with an audited denial — never silently skipped.
4. **Audit always.** Every execute AND every denial writes a hash-chain audit
   row (``AuditCategory.CONTAINMENT``) stamping the acting user as
   ``approver_id`` plus the tool response and outcome. Nothing runs, and nothing
   is refused, without a row.
5. **Org-scoped.** The safelist policy and the audit stamp use the caller's
   ``org_id``; there is no cross-tenant execution or safelist read.

The public functions are **result-returning** (never raise for a business
denial): they emit a durable audit row and hand the route an outcome + HTTP
status. That matters because raising past the request boundary would roll the
denial audit row back — the denial must survive as a first-class ledger fact.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from btagent_shared.security.safelist import SafelistPolicy
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.services import response_safelist_service
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.services.containment_execute")


def _mock_connectors_enabled() -> bool:
    """Fleet-wide mock switch (default on). Mirrors the MCP servers' own default."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").strip().lower() == "true"


# --------------------------------------------------------------------------- #
# Connector/MCP dispatch (mock-first; live stays guarded)
# --------------------------------------------------------------------------- #

# action_type "isolate_host" → connector → (module, class, method, target_kwarg).
_ISOLATION_ROUTES: dict[str, tuple[str, str, str, str]] = {
    "crowdstrike": (
        "btagent_agents.mcp.servers.crowdstrike_mcp",
        "CrowdStrikeMCPServer",
        "cs_isolate_host",
        "hostname",
    ),
    "defender": (
        "btagent_agents.mcp.servers.defender_endpoint_mcp",
        "DefenderEndpointMCPServer",
        "mde_isolate_machine",
        "hostname",
    ),
    "cortex": (
        "btagent_agents.mcp.servers.cortex_mcp",
        "CortexXDRMCPServer",
        "cortex_isolate_endpoint",
        "endpoint_id",
    ),
}


async def _dispatch(action_type: str, connector: str, target: str) -> dict[str, Any]:
    """Dispatch one containment/block action through the connector/MCP layer.

    Mock-first: in mock mode the flagship isolation actions route to the real
    (mock) EDR MCP servers so the connector layer is genuinely exercised;
    everything else returns a synthesized mock "applied" envelope. In LIVE mode
    this raises ``NotImplementedError`` — the guarded live connector paths are
    NOT unbolted by #106, so a misconfigured prod flip fails closed rather than
    performing a real destructive action from this half-built path.
    """
    if not _mock_connectors_enabled():
        raise NotImplementedError(
            "Live containment execution is not enabled. Connectors remain "
            "mock-first (BTAGENT_MOCK_CONNECTORS); the live dispatch path is a "
            "guarded placeholder and #106 does not unbolt it."
        )

    if action_type == "isolate_host" and connector in _ISOLATION_ROUTES:
        import importlib

        from btagent_agents.mcp.policy import guard_dispatch

        module, cls_name, method, target_kwarg = _ISOLATION_ROUTES[connector]
        # A3: enforce the manifest policy at this direct dispatch site — the
        # router gate never sees these calls. ``hitl_approved=True`` because
        # this function is only reachable through the backend approve→execute
        # double-gate (RBAC + ``approved`` flag + safelist screen); the
        # approval is server-side state, never model-supplied (#374). A
        # refusal (undeclared tool, TLP-blocked capability) raises
        # MCPPolicyRefused, which the callers record as an audited denial.
        guard_dispatch(method, hitl_approved=True)
        server_cls = getattr(importlib.import_module(module), cls_name)
        server = server_cls(mock_mode=True)
        result = await getattr(server, method)(**{target_kwarg: target})
        return dict(result)

    # No live-capable mock method wired for this (action, connector) pair — return
    # a deterministic mock envelope so the audit + change-record flow still runs.
    # This is where the #117 cloud IAM actions land: live cloud control-plane
    # connectors are deferred to #100, so they are mock-only here and the live
    # branch above already refused before reaching this point.
    return {
        "status": "success",
        "is_mock": True,
        "action": action_type,
        "connector": connector,
        "target": target,
        "note": "mock dispatch — no live connector wired for this action",
    }


def _outcome_for(tool_response: dict[str, Any]) -> AuditOutcome:
    status = str(tool_response.get("status", "success")).lower()
    return AuditOutcome.SUCCESS if status == "success" else AuditOutcome.FAILURE


# --------------------------------------------------------------------------- #
# Response-action execution (UC-3.2 tactical steps)
# --------------------------------------------------------------------------- #

# Response action_types whose target is a blocklist entry (safelist applies).
_BLOCK_ACTION_TYPES: frozenset[str] = frozenset({"block_ip", "block_domain"})

# Cloud IAM control-plane action_types (#117 Phase C bullet 2). Their target is
# a cloud *principal* (ARN / service-account email / object id), so they screen
# against the org principal safelist instead of the IP/domain sets — same
# chokepoint, same audited denial, same single dispatch path below.
_CLOUD_IAM_ACTION_TYPES: frozenset[str] = frozenset(
    {"revoke_role", "freeze_access_key", "detach_policy"}
)

# Identity action_types whose target is an *account* rather than an address.
#
# ``disable_account`` screens the same principal safelist the cloud IAM actions
# do. An account identifier is the same class of thing the ``principal`` entry
# kind already holds (ARN / service-account email / object id), matched exactly
# and case-insensitively, and the always-on account-root guard applies to it for
# free — disabling a cloud account root is precisely the outage the safelist
# exists to prevent.
#
# This was unscreened until now: the safelist described itself as a
# "collateral-outage guard", and disabling the break-glass admin is the textbook
# collateral outage, but only blocklist and cloud-IAM targets were ever checked.
# Nothing destructive reaches a real system today (``_dispatch`` refuses in live
# mode), so the gap was latent rather than exploitable — which is exactly why it
# is cheap to close before #100/#106 unbolt the live paths.
_ACCOUNT_ACTION_TYPES: frozenset[str] = frozenset({"disable_account"})

# Action types screened against the principal safelist (cloud IAM + accounts).
_PRINCIPAL_SCREENED_ACTION_TYPES: frozenset[str] = _CLOUD_IAM_ACTION_TYPES | _ACCOUNT_ACTION_TYPES

# Every action_type that must be safelist-screened before any dispatch.
_SAFELIST_SCREENED_ACTION_TYPES: frozenset[str] = (
    _BLOCK_ACTION_TYPES | _PRINCIPAL_SCREENED_ACTION_TYPES
)

#: Destructive action types the safelist **cannot** screen, and why.
#:
#: Named rather than left implicit, because an unscreened destructive action is
#: indistinguishable from a screened one at this call site — the ``if
#: action_type in _SAFELIST_SCREENED_ACTION_TYPES`` simply does not fire, and
#: nothing says whether that was a decision or an oversight. For ``disable_account``
#: it was an oversight.
#:
#: These two remain open because their target is a host, and the safelist has no
#: host entry kind: ``ip`` is an exact IP match, and an isolation target is a
#: hostname or device id. Adding one needs a matching rule (exact hostname?
#: FQDN suffix? device id?) that is an operator-facing product decision, not a
#: mechanical extension of what already exists.
#:
#: ``test_containment_safelist_coverage.py`` fails if this list grows.
UNSCREENED_DESTRUCTIVE_ACTION_TYPES: dict[str, str] = {
    "isolate_host": (
        "target is a hostname / device id; the safelist has no host entry kind "
        "(ip matches exact addresses only)"
    ),
    "kill_process": (
        "target is a process on a host; screening it needs the same host entry "
        "kind isolate_host does"
    ),
}


async def execute_response_action(
    db: AsyncSession,
    *,
    actor_id: str,
    org_id: str,
    action_id: str,
    action_type: str,
    connector: str,
    target: str,
    description: str = "",
    approved: bool,
) -> dict[str, Any]:
    """Execute one approved :class:`ResponseAction` and record it.

    Double-gated (RBAC at the route + ``approved`` here). Block-type actions and
    cloud IAM control-plane actions are safelist-screened before dispatch; a
    safelisted target is refused with an audited denial. Every path writes
    exactly one audit row stamping ``actor_id`` as approver. Returns a result
    dict carrying ``http_status``.
    """
    resource = f"response_action:{action_id}"
    action = f"execute:{action_type}"

    if approved is not True:
        return await _record_denial(
            db,
            actor_id=actor_id,
            org_id=org_id,
            action=action,
            resource=resource,
            target=target,
            tool=connector,
            reason="Action is not approved (the HITL half of the double-gate is missing).",
        )

    # Safelist guard (never act on a safelisted target). One screen covers both
    # blocklist targets and cloud IAM principals — see _target_safelisted.
    if action_type in _SAFELIST_SCREENED_ACTION_TYPES:
        policy = await response_safelist_service.load_policy(db, org_id=org_id)
        if _target_safelisted(policy, action_type, target):
            noun = (
                "never-touch" if action_type in _PRINCIPAL_SCREENED_ACTION_TYPES else "never-block"
            )
            return await _record_denial(
                db,
                actor_id=actor_id,
                org_id=org_id,
                action=action,
                resource=resource,
                target=target,
                tool=connector,
                reason=f"Target is on the org {noun} safelist (collateral-outage guard).",
            )

    from btagent_agents.mcp.policy import MCPPolicyRefused

    try:
        tool_response = await _dispatch(action_type, connector, target)
    except MCPPolicyRefused as refusal:
        # A3/A7 lesson: a dispatch-layer refusal must land on the ledger, not
        # surface as an unaudited 500.
        return await _record_denial(
            db,
            actor_id=actor_id,
            org_id=org_id,
            action=action,
            resource=resource,
            target=target,
            tool=connector,
            reason=f"Manifest policy refused dispatch: {refusal.verdict.reason}",
            extra={"policy_status": refusal.verdict.status},
        )
    outcome = _outcome_for(tool_response)

    audit = await AuditTrail(db).record(
        actor=actor_id,
        org_id=org_id,
        category=AuditCategory.CONTAINMENT,
        action=action,
        resource=resource,
        outcome=outcome,
        details={
            "approver_id": actor_id,
            "connector": connector,
            "target": target,
            "description": description,
            "mock": tool_response.get("is_mock", True),
            "tool_response": tool_response,
        },
    )
    logger.info(
        "containment execute org=%s actor=%s action=%s target=%s outcome=%s audit=%s",
        org_id,
        actor_id,
        action_type,
        target,
        outcome.value,
        audit.id,
    )
    return {
        "http_status": 200,
        "executed": outcome == AuditOutcome.SUCCESS,
        "outcome": outcome.value,
        "tool": connector,
        "target": target,
        "tool_response": tool_response,
        "audit_id": audit.id,
        "approver_id": actor_id,
        "change_ref": None,
    }


# --------------------------------------------------------------------------- #
# Bulk-block execution (UC-3.3) — safelist guard + change-management link
# --------------------------------------------------------------------------- #


async def execute_bulk_block(
    db: AsyncSession,
    *,
    actor_id: str,
    org_id: str,
    action_id: str,
    ioc_type: str,
    ioc_value: str,
    tool: str,
    policy_object: str = "",
    rollback: str | None = None,
    approved: bool,
) -> dict[str, Any]:
    """Execute one approved bulk-block :class:`MitigationAction` and record it.

    Order of operations (safety-critical):

    1. ``approved`` gate (HITL half of the double-gate).
    2. **Safelist first** — a safelisted IP/domain is refused with an audited
       denial *before* any dispatch.
    3. Dispatch the block through the connector/MCP layer (mock-first).
    4. Attach a change-management record (ServiceNow SIR, mock-first) and link
       its reference.
    5. Write the success audit row (with the change ref + tool response).
    """
    resource = f"mitigation_action:{action_id}"
    action = "execute:block_ioc"

    # (1) Approval gate.
    if approved is not True:
        return await _record_denial(
            db,
            actor_id=actor_id,
            org_id=org_id,
            action=action,
            resource=resource,
            target=ioc_value,
            tool=tool,
            reason="Action is not approved (the HITL half of the double-gate is missing).",
            extra={"ioc_type": ioc_type},
        )

    # (2) Safelist first — before any dispatch.
    policy = await response_safelist_service.load_policy(db, org_id=org_id)
    if _ioc_safelisted(policy, ioc_type, ioc_value):
        return await _record_denial(
            db,
            actor_id=actor_id,
            org_id=org_id,
            action=action,
            resource=resource,
            target=ioc_value,
            tool=tool,
            reason="IOC is on the org never-block safelist (collateral-outage guard).",
            extra={"ioc_type": ioc_type},
        )

    # (3) Dispatch the block (mock-first).
    tool_response = await _dispatch("block_ioc", tool, ioc_value)
    outcome = _outcome_for(tool_response)

    # (4) Change-management link (mock-first ServiceNow SIR).
    change_ref, change_response = await _attach_change_record(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        tool=tool,
        policy_object=policy_object,
        rollback=rollback,
    )

    # (5) Success audit row.
    audit = await AuditTrail(db).record(
        actor=actor_id,
        org_id=org_id,
        category=AuditCategory.CONTAINMENT,
        action=action,
        resource=resource,
        outcome=outcome,
        details={
            "approver_id": actor_id,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "tool": tool,
            "policy_object": policy_object,
            "change_ref": change_ref,
            "change_response": change_response,
            "mock": tool_response.get("is_mock", True),
            "tool_response": tool_response,
        },
    )
    logger.info(
        "bulk block execute org=%s actor=%s ioc=%s:%s tool=%s change=%s outcome=%s audit=%s",
        org_id,
        actor_id,
        ioc_type,
        ioc_value,
        tool,
        change_ref,
        outcome.value,
        audit.id,
    )
    return {
        "http_status": 200,
        "executed": outcome == AuditOutcome.SUCCESS,
        "outcome": outcome.value,
        "tool": tool,
        "target": ioc_value,
        "tool_response": tool_response,
        "audit_id": audit.id,
        "approver_id": actor_id,
        "change_ref": change_ref,
    }


# --------------------------------------------------------------------------- #
# Safelist helpers
# --------------------------------------------------------------------------- #


def _ioc_safelisted(policy: SafelistPolicy, ioc_type: str, value: str) -> bool:
    t = (ioc_type or "").strip().lower()
    if t == "ip":
        return policy.ip_safelisted(value)
    if t == "domain":
        return policy.domain_safelisted(value)
    if t == "url":
        return policy.url_safelisted(value)
    return False


def _target_safelisted(policy: SafelistPolicy, action_type: str, target: str) -> bool:
    if action_type == "block_ip":
        return policy.ip_safelisted(target)
    if action_type == "block_domain":
        return policy.domain_safelisted(target)
    if action_type in _PRINCIPAL_SCREENED_ACTION_TYPES:
        # Cloud IAM containment targets a *principal*; disabling an account
        # targets the same class of identifier. Both screen the org principal
        # safelist (plus the always-on account-root guard).
        return policy.principal_safelisted(target)
    return False


# --------------------------------------------------------------------------- #
# Audit + change-management helpers
# --------------------------------------------------------------------------- #


async def _record_denial(
    db: AsyncSession,
    *,
    actor_id: str,
    org_id: str,
    action: str,
    resource: str,
    target: str,
    tool: str,
    reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write an audited DENIED row and return a 403 result.

    A refused target is never silently skipped: the denial is a first-class,
    hash-chained audit fact stamping the acting user as approver. Returning
    (rather than raising) lets the request commit the row before the 403 is sent.
    """
    details: dict[str, Any] = {
        "approver_id": actor_id,
        "target": target,
        "tool": tool,
        "reason": reason,
    }
    if extra:
        details.update(extra)
    audit = await AuditTrail(db).record(
        actor=actor_id,
        org_id=org_id,
        category=AuditCategory.CONTAINMENT,
        action=action,
        resource=resource,
        outcome=AuditOutcome.DENIED,
        details=details,
    )
    logger.warning(
        "containment DENIED org=%s actor=%s action=%s target=%s tool=%s reason=%s audit=%s",
        org_id,
        actor_id,
        action,
        target,
        tool,
        reason,
        audit.id,
    )
    return {
        "http_status": 403,
        "executed": False,
        "outcome": AuditOutcome.DENIED.value,
        "message": reason,
        "tool": tool,
        "target": target,
        "audit_id": audit.id,
        "approver_id": actor_id,
        "change_ref": None,
    }


async def _attach_change_record(
    *,
    ioc_type: str,
    ioc_value: str,
    tool: str,
    policy_object: str,
    rollback: str | None,
) -> tuple[str | None, dict[str, Any]]:
    """Open a change-management record for a bulk block (ServiceNow SIR, mock-first).

    Returns ``(change_ref, raw_response)``. Never raises — a change-record hiccup
    must not undo an already-dispatched block; the audit row records whatever the
    ticketing connector returned (including a failure envelope).
    """
    try:
        # Only reached in mock mode — _dispatch() fails closed before this in
        # live mode — so the change link is always the mock SIR ledger here.
        from btagent_agents.mcp.policy import guard_dispatch
        from btagent_agents.mcp.servers.servicenow_mcp import ServiceNowMCPServer

        # A3: manifest gate at the direct dispatch site. Not HITL-gated (a
        # ticket, not an action); a refusal is caught by the best-effort
        # except below — the block already happened, only the change link is
        # skipped and recorded as failed.
        guard_dispatch("snow_create_security_incident")
        snow = ServiceNowMCPServer(mock_mode=_mock_connectors_enabled())
        response = await snow.snow_create_security_incident(
            short_description=f"Containment change: block {ioc_type} {ioc_value}",
            description=(
                f"Bulk IOC block executed via {tool}:{policy_object or 'blocklist'}. "
                f"Rollback: {rollback or 'n/a'}."
            ),
            priority="2-high",
            category="containment",
        )
        change_ref = response.get("number") if isinstance(response, dict) else None
        return change_ref, dict(response) if isinstance(response, dict) else {}
    except Exception as exc:  # noqa: BLE001 - change link is best-effort
        logger.warning("change-record link failed for %s %s: %s", ioc_type, ioc_value, exc)
        return None, {"status": "error", "message": str(exc)}


__all__ = [
    "execute_bulk_block",
    "execute_response_action",
]
