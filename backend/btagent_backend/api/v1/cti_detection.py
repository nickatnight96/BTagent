"""CTI → Detection proposal API (issue #113 slice).

POST /api/v1/cti/propose-detections
    Accept a STIX 2.1 bundle, return Sigma rule proposals.

RBAC: ``hunt:create`` (analyst+).  Proposing detections is a read/generate
action equivalent to creating a new hunt — no execution side-effects.

TLP enforcement:
    TLP:RED bundles are refused with HTTP 403.  The gate is applied in the
    shared :func:`process_stix_bundle` and surfaced here as a 403 response
    so callers get a consistent error.  This matches the existing ioc export
    endpoint (``api/v1/iocs.py:export_stix``) which also 403s on TLP:RED.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.security.tlp import TLPViolation
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import (
    CTIToDetectionRequest,
    CTIToDetectionResponse,
)
from fastapi import APIRouter, Depends, HTTPException

from btagent_backend.api.deps import CurrentUser, get_current_user
from btagent_backend.services.cti_detection_service import CTIDetectionService

logger = logging.getLogger("btagent.api.cti_detection")

router = APIRouter(prefix="/cti", tags=["cti-detection"])

_service = CTIDetectionService()


@router.post(
    "/propose-detections",
    response_model=CTIToDetectionResponse,
    summary="Generate Sigma rule proposals from a STIX 2.1 bundle",
    response_description="List of Sigma rule proposals pending analyst review.",
)
async def propose_detections(
    body: CTIToDetectionRequest,
    user: CurrentUser = Depends(get_current_user),
) -> CTIToDetectionResponse:
    """Convert a STIX 2.1 bundle into Sigma rule proposals.

    Proposals are returned to the caller and are **not** persisted in this
    slice.  An analyst reviews, modifies, accepts, or rejects each proposal
    via the hunt workflow (persistence is deferred to the follow-up PR).

    The endpoint refuses TLP:RED bundles (HTTP 403) and bundles that are
    not valid STIX 2.1 (HTTP 422).  Exactly one of ``stix_bundle`` or
    ``stix_bundle_id`` must be supplied; passing ``stix_bundle_id`` without
    a persisted bundle resolution path returns HTTP 501.

    RBAC: ``hunt:create`` (analyst+).
    """
    user.require_permission("hunt:create")

    # Validate that exactly one input variant is provided
    if body.stix_bundle is None and body.stix_bundle_id is None:
        raise HTTPException(
            status_code=422,
            detail="Exactly one of 'stix_bundle' or 'stix_bundle_id' must be supplied.",
        )

    if body.stix_bundle is not None and body.stix_bundle_id is not None:
        raise HTTPException(
            status_code=422,
            detail="Supply exactly one of 'stix_bundle' or 'stix_bundle_id', not both.",
        )

    # Inline TLP gate for bundle_id (deferred path)
    if body.stix_bundle_id is not None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Bundle-by-id resolution is not yet implemented. "
                "Pass the raw bundle dict in 'stix_bundle' instead."
            ),
        )

    bundle: dict[str, Any] = body.stix_bundle  # type: ignore[assignment]

    try:
        response = _service.propose_from_bundle(bundle=bundle, active_tlp=body.active_tlp)
    except TLPViolation as exc:
        logger.warning(
            "CTI detect proposal refused: TLP violation from user %s — %s",
            user.id,
            exc,
        )
        raise HTTPException(
            status_code=403,
            detail=f"TLP:RED bundles are not permitted for detection proposal. {exc}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return response
