"""Org-policy egress enforcement (EPIC-7 UC-7.2 — the runtime half).

The policy registry landed with storage, an API and a pure evaluator, but
nothing ever consulted it on a *real* egress: ``evaluate_egress_policy`` was
reachable only from the dry-run ``POST /tlp-policies/evaluate``. A CISO could
write "deny report_export of AMBER_STRICT", see the endpoint agree with them,
and watch the export succeed anyway. This module closes that.

**Org policies may only subtract permission, never add it.**

That is the whole design constraint, and it is enforced structurally rather
than by convention:

* the shared, hardcoded gate
  (:func:`btagent_shared.security.assert_tlp_allows_egress`) still runs first
  and is untouched — TLP:RED is refused exactly as before, including the
  recursive payload scan and its fail-closed depth limit;
* this guard runs *after* it, and acts **only** on a
  :attr:`~btagent_shared.security.tlp_policy.PolicyDecision.allowed` of
  ``False``. It never acts on ``True``.

The consequence is that ``ALLOW`` and ``DOWNGRADE_THEN_ALLOW`` policies remain
inert at runtime, deliberately: honouring them would widen a default-deny gate
protecting TLP:RED, which is a decision for whoever owns the enclave, not
something to switch on as a side effect of making DENY work. A ``deny`` policy,
by contrast, can only ever refuse an egress the baseline would have permitted,
so it is safe to enforce immediately — and until it is, a governance control
the product advertises does not exist.

Evaluation is best-effort in one direction only: a policy *lookup* that fails
must not silently open a channel, but neither should a DB blip break exports
that the baseline already cleared. Since the baseline has, by this point,
already approved the egress, a lookup failure leaves us exactly where the
system was before this module existed — so it is logged loudly and the egress
proceeds. Lookup failure is not a deny signal; it is an absence of one.
"""

from __future__ import annotations

import logging

from btagent_shared.security.tlp import TLPViolation
from btagent_shared.security.tlp_policy import TLPViolationEvent, emit_violation
from btagent_shared.types.config import TLP
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.services.tlp_policy_service import TLPPolicyService

logger = logging.getLogger("btagent.security.tlp_egress_guard")


def _coerce(tlp: TLP | str | None) -> TLP:
    """Resolve a classification to a TLP, failing closed on garbage.

    Mirrors :func:`btagent_shared.security.tlp._resolve_classification`: an
    absent classification is GREEN (the configured default), but one that was
    *supplied* and cannot be parsed resolves to RED so a typo can never buy a
    laxer policy match than the operator intended.
    """
    if isinstance(tlp, TLP):
        return tlp
    if tlp is None:
        return TLP.GREEN
    try:
        return TLP(str(tlp).lower())
    except ValueError:
        return TLP.RED


async def assert_org_policy_allows_egress(
    db: AsyncSession,
    *,
    org_id: str,
    tlp: TLP | str | None,
    egress_kind: str,
) -> None:
    """Refuse an egress that this org's policies explicitly deny.

    Call *after* :func:`btagent_shared.security.assert_tlp_allows_egress`, not
    instead of it — this is the org-scoped layer on top of the universal
    baseline, and on its own it does not scan the payload.

    Raises
    ------
    TLPViolation
        If a matching policy denies this ``(tlp, egress_kind)`` pair. A
        ``tlp.violation_attempt`` event carrying the matched policy id is
        emitted first, so the ledger records *which* governance decision
        stopped the egress rather than just that something did.
    """
    resolved = _coerce(tlp)
    try:
        decision = await TLPPolicyService(db).evaluate(
            org_id=org_id, tlp=resolved, egress_kind=egress_kind
        )
    except Exception:  # noqa: BLE001 - see module docstring: absence of a deny, not a deny
        logger.exception(
            "TLP policy lookup failed for org=%s kind=%s; proceeding on the baseline "
            "gate's decision alone (org deny policies NOT applied to this egress)",
            org_id,
            egress_kind,
        )
        return

    if decision.allowed:
        # Never act on an allow: the baseline already had the final say on
        # whether this may leave, and widening it is not this layer's job.
        return

    logger.error(
        "TLP egress blocked by org policy: org=%s kind=%s tlp=%s policy=%s reason=%s",
        org_id,
        egress_kind,
        resolved.value,
        decision.matched_policy_id,
        decision.reason,
    )
    emit_violation(
        TLPViolationEvent(
            tlp=resolved,
            egress_kind=egress_kind,
            channel=f"egress:{egress_kind}",
            org_id=org_id,
            matched_policy_id=decision.matched_policy_id,
            reason=decision.reason or "denied by org TLP policy",
        )
    )
    raise TLPViolation(resolved, f"egress:{egress_kind}")


__all__ = ["assert_org_policy_allows_egress"]
