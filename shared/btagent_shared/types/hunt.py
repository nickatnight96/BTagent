"""Base enumerations for the Phase 6 proactive threat-hunting subsystem.

These are the cross-cutting vocabulary shared by every hunt source (hunt
packs, behavioral, identity, cloud, cross-investigation, agentic). The
concrete finding/cluster/suppression schemas live in
:mod:`btagent_shared.types.hunt_finding`; the pure clustering + suppression
logic lives in :mod:`btagent_shared.hunt`.
"""

from __future__ import annotations

from enum import StrEnum


class HuntDomain(StrEnum):
    """The detection domain a hunt finding belongs to.

    One per Phase 6 hunt agent. Used to bucket findings and to pick the
    right enrichment / promotion path downstream.
    """

    SIGMA = "sigma"
    BEHAVIORAL = "behavioral"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CROSS_INVESTIGATION = "cross_investigation"
    AGENTIC = "agentic"


class HuntSource(StrEnum):
    """What produced a finding.

    Distinct from :class:`HuntDomain`: a single domain can be reached by
    more than one source (e.g. a scheduled pack run vs. a manual analyst
    hunt both land in ``SIGMA``).
    """

    HUNT_PACK = "hunt_pack"
    BEHAVIORAL = "behavioral"
    IDENTITY = "identity"
    CLOUD = "cloud"
    CROSS_INVESTIGATION = "cross_investigation"
    AGENTIC = "agentic"
    MANUAL = "manual"


class HuntFindingState(StrEnum):
    """Lifecycle state of a single hunt finding.

    * ``NEW`` — just emitted by a hunt source, not yet clustered.
    * ``CLUSTERED`` — assigned to a :class:`HuntFindingCluster`.
    * ``TRIAGED`` — an analyst has reviewed it (acknowledged, not actioned).
    * ``SUPPRESSED`` — matched an active suppression rule; hidden from the
      default triage inbox.
    * ``PROMOTED`` — escalated into a full investigation.
    * ``DISMISSED`` — explicitly closed as not-interesting (one-off, no rule).
    """

    NEW = "new"
    CLUSTERED = "clustered"
    TRIAGED = "triaged"
    SUPPRESSED = "suppressed"
    PROMOTED = "promoted"
    DISMISSED = "dismissed"


class SuppressionState(StrEnum):
    """Lifecycle of a suppression rule.

    Suppressions are deliberately *not* permanent: a stale-suppression
    sweep (the Phase 6 arq cron) flips ``ACTIVE`` rules that are past their
    ``reconfirm_at`` to ``NEEDS_RECONFIRM`` so a human re-affirms that the
    noise is still expected, and past ``expires_at`` to ``EXPIRED``.
    """

    ACTIVE = "active"
    NEEDS_RECONFIRM = "needs_reconfirm"
    EXPIRED = "expired"
    REVOKED = "revoked"
