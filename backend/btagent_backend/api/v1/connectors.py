"""Connector catalog API — read-only capability introspection (#100 Layer 3).

Surfaces the engine's connector manifests (the declarative capability
self-description every integration node carries) so the frontend Settings →
Integrations view — and planners — can answer "what connectors are
installed, what can each do, what does it emit, what needs HITL?" without
reaching into the engine.

Read-only + RBAC (``connector:view``, analyst+). Manifests are secret-free
(credential *types* only), so there is nothing to redact.
"""

from __future__ import annotations

import logging

from btagent_shared.types.connector import ConnectorManifest, OCSFEventClass
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from btagent_backend.api.deps import CurrentUser, get_current_user
from btagent_backend.services import connector_catalog

logger = logging.getLogger("btagent.api.connectors")

router = APIRouter(prefix="/connectors", tags=["connectors"])


class ConnectorSummary(BaseModel):
    """Compact catalog-row view (the list endpoint)."""

    name: str
    version: str
    description: str
    transport: str
    auth: str
    query_count: int
    action_count: int
    stream_count: int
    # True when any capability is HITL-gated — the UI badges these.
    has_hitl_actions: bool
    # Union of OCSF classes across all capabilities (dedup, sorted).
    ocsf_emits: list[str]


class ConnectorListResponse(BaseModel):
    items: list[ConnectorSummary]
    total: int


def _summary(manifest: ConnectorManifest) -> ConnectorSummary:
    caps = (*manifest.queries, *manifest.actions, *manifest.streams)
    emits: set[str] = set()
    for cap in caps:
        emits.update(c.value for c in cap.ocsf_emits)
    return ConnectorSummary(
        name=manifest.name,
        version=manifest.version,
        description=manifest.description,
        transport=manifest.transport.value,
        auth=manifest.auth.value,
        query_count=len(manifest.queries),
        action_count=len(manifest.actions),
        stream_count=len(manifest.streams),
        has_hitl_actions=any(getattr(c, "hitl_required", False) for c in caps),
        ocsf_emits=sorted(emits),
    )


@router.get("", response_model=ConnectorListResponse)
async def list_connectors(
    emits: OCSFEventClass | None = Query(
        None,
        description=(
            "Filter to connectors with at least one capability emitting this "
            "OCSF event class (e.g. 'authentication')."
        ),
    ),
    has_actions: bool | None = Query(
        None,
        description="Filter to connectors that do (true) or don't (false) declare actions.",
    ),
    user: CurrentUser = Depends(get_current_user),
) -> ConnectorListResponse:
    """List installed connectors and their capability summaries."""
    user.require_permission("connector:view")

    manifests = connector_catalog.list_manifests()
    if emits is not None:
        manifests = [m for m in manifests if m.capabilities_emitting(emits)]
    if has_actions is not None:
        manifests = [m for m in manifests if bool(m.actions) is has_actions]

    return ConnectorListResponse(items=[_summary(m) for m in manifests], total=len(manifests))


@router.get("/{name}", response_model=ConnectorManifest)
async def get_connector(
    name: str,
    user: CurrentUser = Depends(get_current_user),
) -> ConnectorManifest:
    """Full manifest for one connector (all capability tables)."""
    user.require_permission("connector:view")

    manifest = connector_catalog.get_manifest(name)
    if manifest is None:
        raise HTTPException(status_code=404, detail=f"Connector '{name}' not installed")
    return manifest
