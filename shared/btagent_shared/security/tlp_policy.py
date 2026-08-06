"""TLP egress policy registry + violation events (UC-7.2).

The hardcoded egress gate in :mod:`btagent_shared.security.tlp` is
default-deny for TLP:RED. This module layers an **org-scoped policy
registry** on top, expressing what a CISO has approved for a given
egress channel and classification. It also defines the
``tlp.violation_attempt`` event emitted whenever an egress is refused,
plus a process-local *sink* so the host application can forward those
events to its own alerter (event bus / PagerDuty / Slack) without
``btagent_shared`` taking a dependency on any of them.

**How much of this is enforced at runtime, precisely.** The evaluator
below is pure and models all three actions, but only its *restrictive*
half currently governs real egress:

* ``DENY`` — **enforced.** ``btagent_backend.services.tlp_egress_guard``
  consults an org's policies after the baseline gate has run and refuses
  the egress if one denies it.
* ``ALLOW`` / ``DOWNGRADE_THEN_ALLOW`` — **inert at runtime.** Honouring
  them would widen the default-deny gate that protects TLP:RED, which is
  an enclave-owner's decision rather than an implementation detail, so
  the guard never acts on a permit. They evaluate correctly here and via
  the dry-run ``POST /tlp-policies/evaluate``, and are ready to be wired
  the day that call is made.

Design constraints (why it lives here and looks like this):

* ``btagent_shared`` stays dependency-light — no event-bus / DB / HTTP
  imports. The sink is a plain callable the host registers, mirroring
  the LLM-client registry pattern used elsewhere.
* **Default-deny is preserved.** With no matching policy, RED egress is
  refused exactly as before.
* Pure, synchronous, side-effect-free evaluation so it can be called
  from sync code, coroutines, hooks, or services alike.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import TLP

logger = logging.getLogger("btagent.security.tlp_policy")

# Restriction ordering — higher rank == more restricted. Used to verify a
# "downgrade" genuinely lowers restriction rather than silently raising it.
_TLP_RANK: dict[TLP, int] = {
    TLP.WHITE: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}


def tlp_rank(tlp: TLP) -> int:
    """Return the restriction rank of *tlp* (higher == more restricted)."""
    return _TLP_RANK[tlp]


def _aware(dt: datetime) -> datetime:
    """Treat a naive datetime as UTC so comparisons never raise."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class EgressKind(StrEnum):
    """The channels an org's TLP policy can govern.

    Every one of these is a real gate: each value is passed to
    ``assert_org_policy_allows_egress`` at a call site that can refuse the
    operation. Naming them here rather than as bare strings is what lets the
    frontend's picker be generated from the vocabulary instead of typed out —
    ``report_export`` was gated and tested on the backend while the SPA's
    hand-written list offered only the other four, so no operator could write
    a policy restricting report exports by TLP. The control existed and could
    not be configured.

    ``test_shared_enum_ts_parity`` compares this against
    ``frontend/src/types/containment.ts`` from here on.
    """

    STIX_EXPORT = "stix_export"
    REPORT_EXPORT = "report_export"
    KNOWLEDGE_INGEST = "knowledge_ingest"
    MCP_RETURN = "mcp_return"
    EVENT_EMIT = "event_emit"


class TLPPolicyAction(StrEnum):
    """What an egress policy does when it matches."""

    ALLOW = "allow"
    DENY = "deny"
    DOWNGRADE_THEN_ALLOW = "downgrade_then_allow"


class TLPPolicy(BaseModel):
    """A CISO-approved, org-scoped exception to the default-deny egress gate.

    Matching is conjunctive over the (optional) ``egress_kinds`` and
    ``applies_to_tlp`` conditions; an empty condition tuple matches any
    value. An expired policy (``valid_until`` in the past) never matches.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    org_id: str
    action: TLPPolicyAction

    # Match conditions. Empty tuple == "matches any".
    egress_kinds: tuple[str, ...] = ()
    applies_to_tlp: tuple[TLP, ...] = ()

    # Required (and only meaningful) when action == DOWNGRADE_THEN_ALLOW.
    downgrade_to: TLP | None = None

    # Governance metadata — who approved, why, and until when.
    approver_id: str = ""
    rationale: str = ""
    valid_until: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def matches(self, *, tlp: TLP, egress_kind: str, now: datetime) -> bool:
        """Whether this policy applies to a ``(tlp, egress_kind)`` egress at ``now``."""
        if self.valid_until is not None and _aware(now) > _aware(self.valid_until):
            return False
        if self.egress_kinds and egress_kind not in self.egress_kinds:
            return False
        if self.applies_to_tlp and tlp not in self.applies_to_tlp:
            return False
        return True


class PolicyDecision(BaseModel):
    """The outcome of evaluating egress against the policy registry."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    effective_tlp: TLP
    action: TLPPolicyAction
    matched_policy_id: str | None = None
    reason: str = ""


def evaluate_egress_policy(
    *,
    tlp: TLP,
    egress_kind: str,
    policies: Iterable[TLPPolicy] = (),
    now: datetime | None = None,
) -> PolicyDecision:
    """Decide whether ``tlp`` data may egress via ``egress_kind``.

    Baseline (no matching policy): **default-deny** — TLP:RED is refused,
    everything below RED is allowed. Policies may only widen (allow /
    downgrade) or explicitly deny. Precedence among matching policies is
    fail-safe: an explicit DENY wins, then DOWNGRADE_THEN_ALLOW, then ALLOW.

    The caller is responsible for passing only the *relevant org's*
    policies — this function does not filter by ``org_id``.

    This function is pure and models all three actions. Which of its
    outcomes actually govern a live egress is a separate question — see
    the module docstring: today only ``allowed=False`` is acted on.
    """
    now = _aware(now or datetime.now(UTC))
    matching = [p for p in policies if p.matches(tlp=tlp, egress_kind=egress_kind, now=now)]

    deny = next((p for p in matching if p.action == TLPPolicyAction.DENY), None)
    if deny is not None:
        return PolicyDecision(
            allowed=False,
            effective_tlp=tlp,
            action=TLPPolicyAction.DENY,
            matched_policy_id=deny.id,
            reason="explicit deny policy",
        )

    downgrade = next(
        (p for p in matching if p.action == TLPPolicyAction.DOWNGRADE_THEN_ALLOW), None
    )
    if downgrade is not None:
        target = downgrade.downgrade_to or TLP.GREEN
        if tlp_rank(target) < tlp_rank(tlp):
            return PolicyDecision(
                allowed=True,
                effective_tlp=target,
                action=TLPPolicyAction.DOWNGRADE_THEN_ALLOW,
                matched_policy_id=downgrade.id,
                reason=f"downgraded {tlp.value}->{target.value} by policy",
            )
        # Target isn't actually less restricted — honour the allow intent
        # but don't raise the classification.
        return PolicyDecision(
            allowed=True,
            effective_tlp=tlp,
            action=TLPPolicyAction.DOWNGRADE_THEN_ALLOW,
            matched_policy_id=downgrade.id,
            reason="downgrade target not lower; allowed at original classification",
        )

    allow = next((p for p in matching if p.action == TLPPolicyAction.ALLOW), None)
    if allow is not None:
        return PolicyDecision(
            allowed=True,
            effective_tlp=tlp,
            action=TLPPolicyAction.ALLOW,
            matched_policy_id=allow.id,
            reason="explicit allow policy",
        )

    if tlp == TLP.RED:
        return PolicyDecision(
            allowed=False,
            effective_tlp=tlp,
            action=TLPPolicyAction.DENY,
            reason="default-deny: TLP:RED",
        )
    return PolicyDecision(
        allowed=True,
        effective_tlp=tlp,
        action=TLPPolicyAction.ALLOW,
        reason="default-allow: classification below RED",
    )


# --------------------------------------------------------------------------- #
# Violation events + sink registry
# --------------------------------------------------------------------------- #


class TLPViolationEvent(BaseModel):
    """Emitted whenever a TLP-classified payload is refused egress.

    The host registers a sink via :func:`set_violation_sink` to forward
    these to its alerter; the egress gate calls :func:`emit_violation`.
    """

    model_config = ConfigDict(frozen=True)

    event_type: str = "tlp.violation_attempt"
    tlp: TLP
    egress_kind: str
    channel: str
    org_id: str | None = None
    matched_policy_id: str | None = None
    reason: str = ""
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


ViolationSink = Callable[[TLPViolationEvent], None]

_violation_sink: ViolationSink | None = None


def set_violation_sink(sink: ViolationSink) -> None:
    """Register the process-local sink for ``tlp.violation_attempt`` events."""
    global _violation_sink
    _violation_sink = sink


def clear_violation_sink() -> None:
    """Remove the registered sink (no-op if none registered)."""
    global _violation_sink
    _violation_sink = None


def get_violation_sink() -> ViolationSink | None:
    """Return the registered sink, or ``None``."""
    return _violation_sink


def emit_violation(event: TLPViolationEvent) -> None:
    """Best-effort dispatch to the registered sink. **Never raises.**

    Alerting must never break egress enforcement, so a sink that throws is
    logged and swallowed.
    """
    sink = _violation_sink
    if sink is None:
        return
    try:
        sink(event)
    except Exception:  # noqa: BLE001 - alerting must never break the egress path
        logger.exception("TLP violation sink raised; swallowing to protect egress enforcement")


__all__ = [
    "PolicyDecision",
    "TLPPolicy",
    "EgressKind",
    "TLPPolicyAction",
    "TLPViolationEvent",
    "ViolationSink",
    "clear_violation_sink",
    "emit_violation",
    "evaluate_egress_policy",
    "get_violation_sink",
    "set_violation_sink",
    "tlp_rank",
]
