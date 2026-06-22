"""CTI → Detection service (issue #113 slice).

Thin shell that validates a STIX bundle and delegates to the pure-logic
core in :mod:`btagent_shared.hunt.cti_to_detection`.

This service layer exists so the API route (and any future background
task or event consumer) share a single call site, and so the pure-logic
core can stay in ``shared/`` without importing FastAPI or DB models.

Scope for this slice
--------------------
- Accepts a raw STIX bundle dict (the ``stix_bundle_id`` resolution path
  is left as a TODO for the follow-up PR that adds proposal persistence
  and bundle-by-id lookup).
- Applies TLP gating via the shared gate (TLP:RED bundles raise
  :class:`btagent_shared.security.TLPViolation`).
- Returns :class:`CTIToDetectionResponse` — proposals are *not* persisted
  in this slice.

Telemetry hook
--------------
The ``# TELEMETRY_HOOK`` comment below marks the insertion point for
validation telemetry once issue #118 (rule-quality telemetry) lands.
Replace the pass statement with your telemetry emit call.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.hunt.cti_to_detection import process_stix_bundle
from btagent_shared.security.tlp import TLPViolation
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import CTIToDetectionResponse

logger = logging.getLogger("btagent.services.cti_detection")


class CTIDetectionService:
    """Produce Sigma rule proposals from a STIX 2.1 bundle.

    Usage::

        svc = CTIDetectionService()
        response = svc.propose_from_bundle(bundle=my_bundle, active_tlp=TLP.GREEN)
        for proposal in response.proposals:
            print(proposal.sigma_yaml)
    """

    def propose_from_bundle(
        self,
        *,
        bundle: dict[str, Any],
        active_tlp: TLP = TLP.GREEN,
    ) -> CTIToDetectionResponse:
        """Convert a raw STIX 2.1 bundle into Sigma rule proposals.

        Parameters
        ----------
        bundle:
            Raw STIX 2.1 bundle dict (``{"type": "bundle", "objects": [...]}``)
        active_tlp:
            TLP classification for this operation.  TLP:RED is refused.

        Returns
        -------
        CTIToDetectionResponse
            Proposals + skipped records.

        Raises
        ------
        TLPViolation
            If ``active_tlp`` is :attr:`TLP.RED` or the bundle contains any
            TLP:RED-marked objects.
        ValueError
            If ``bundle`` is not a dict or is missing the ``"type"`` key.
        """
        if not isinstance(bundle, dict):
            raise ValueError("stix_bundle must be a dict")
        if bundle.get("type") != "bundle":
            raise ValueError(
                f"Expected a STIX bundle (type='bundle'), got type={bundle.get('type')!r}"
            )

        logger.info(
            "CTI detection pipeline: processing bundle %s with TLP=%s (%d objects)",
            bundle.get("id", "<no-id>"),
            active_tlp,
            len(bundle.get("objects", [])),
        )

        response = process_stix_bundle(bundle, active_tlp=active_tlp)

        # TELEMETRY_HOOK: emit proposal telemetry for #118 here.
        # e.g. emit_cti_detection_telemetry(response, bundle_id=bundle.get("id"))
        # (no-op until #118 lands)

        logger.info(
            "CTI detection pipeline complete: %d proposals, %d skipped",
            len(response.proposals),
            len(response.skipped),
        )
        return response

    def propose_from_bundle_id(
        self,
        *,
        bundle_id: str,
        active_tlp: TLP = TLP.GREEN,
    ) -> CTIToDetectionResponse:
        """Resolve a previously-imported bundle by ID and produce proposals.

        NOT IMPLEMENTED in this slice.  The bundle-by-id resolution path
        requires proposal persistence (deferred to the follow-up PR).

        Raises
        ------
        NotImplementedError
            Always — this path is a stub for the next slice.
        """
        raise NotImplementedError(
            f"Bundle-by-id resolution (bundle_id={bundle_id!r}) is deferred to the "
            "proposal-persistence follow-up PR.  Pass the raw bundle dict via "
            "propose_from_bundle() instead."
        )


__all__ = ["CTIDetectionService"]
