"""OCSF normalizer middleware — validates output OCSF event-class claims.

Layer 2 of the connector strategy (#100): every integration capability
declares the OCSF event classes its output can contain. This
middleware enforces that contract on ``after_run``:

* If the output payload carries an ``ocsf_event_class`` field (or a
  list of them under ``ocsf_emits`` / ``events[*].class``), every value
  must appear in the capability's declared ``ocsf_emits``.
* If the manifest declares ``ocsf_emits=[]`` (capability emits raw
  / vendor-shaped data), the middleware skips enforcement.
* If the output declares no OCSF class at all, the middleware logs a
  warning (via context metadata) but does not refuse — many existing
  connectors haven't been retrofitted yet.

The normalizer also writes a single ``OCSFEmitSummary`` to
``ctx.metadata[OCSF_SUMMARY_KEY]`` so downstream coverage-map nodes
(EPIC-4 UC-4.2) can aggregate which classes were exercised in a run.

Design notes:

1. **Outputs only.** Inputs aren't OCSF-shaped (they're plain Pydantic
   models from workflow authors). Inputs go through the
   ClassificationMiddleware for TLP, this middleware for OCSF.
2. **Schema is duck-typed.** Different connectors put OCSF tags in
   different places (top-level ``ocsf_event_class``, per-event
   ``events[*].class``, ``ocsf_emits`` list). The middleware accepts
   all three shapes — the canonical shape is captured below.
3. **No mutation.** The middleware *validates*; transforming raw
   vendor data into OCSF shape is the job of the connector itself
   (with a Transform node where needed).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from btagent_shared.types.connector import ConnectorManifest, OCSFEventClass
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.middleware.base import Middleware
from btagent_engine.middleware.connector_policy import (
    CAPABILITY_ID_KEY,
    MANIFEST_NAME_KEY,
)

logger = logging.getLogger("btagent.middleware.ocsf_normalize")

if TYPE_CHECKING:
    from btagent_engine.node import Node, NodeContext


OCSF_SUMMARY_KEY = "connector.ocsf_summary"


class OCSFContractViolation(Exception):
    """Output declared an OCSF event class the manifest didn't permit.

    Almost always a connector bug (the manifest claims to emit
    ``authentication`` but the output actually carries
    ``network_activity``). Failing loud here prevents drift between
    declared and actual schemas.
    """


class OCSFEmitSummary(BaseModel):
    """Per-run summary written to ctx.metadata for downstream consumers."""

    model_config = ConfigDict(extra="forbid")

    connector: str = ""
    capability: str = ""
    declared: list[OCSFEventClass] = Field(default_factory=list)
    observed: list[OCSFEventClass] = Field(default_factory=list)
    undeclared_seen: list[str] = Field(
        default_factory=list,
        description="OCSF class strings seen on the output that the "
        "manifest does not declare. Empty == no contract violations.",
    )


def _extract_ocsf_claims(payload: Any) -> list[str]:
    """Pull every OCSF-class string the output payload exposes.

    Accepts three shapes:
      1. top-level field ``ocsf_event_class: str``
      2. top-level field ``ocsf_emits: list[str]``
      3. per-event field ``events: list[{class: str, ...}]``

    Returns the de-duplicated list of raw class strings; the caller
    parses them into the OCSFEventClass enum.
    """
    if isinstance(payload, BaseModel):
        payload = payload.model_dump()
    if not isinstance(payload, dict):
        return []

    seen: list[str] = []

    top_class = payload.get("ocsf_event_class")
    if isinstance(top_class, str):
        seen.append(top_class)

    top_emits = payload.get("ocsf_emits")
    if isinstance(top_emits, list):
        seen.extend(c for c in top_emits if isinstance(c, str))

    events = payload.get("events")
    if isinstance(events, list):
        for ev in events:
            if isinstance(ev, dict):
                cls = ev.get("class")
                if isinstance(cls, str):
                    seen.append(cls)

    # Dedupe preserving order
    return list(dict.fromkeys(seen))


def _parse(claim: str) -> OCSFEventClass | None:
    try:
        return OCSFEventClass(claim)
    except ValueError:
        return None


class OCSFNormalizerMiddleware(Middleware):
    """Validate that the node's output OCSF claims match the manifest."""

    name = "ocsf_normalizer"

    async def after_run(
        self,
        node: Node,
        input: BaseModel,
        output: BaseModel,
        ctx: NodeContext,
    ) -> None:
        manifest = getattr(node.__class__, "manifest", None)
        if not isinstance(manifest, ConnectorManifest):
            return

        # Reuse the capability id captured by ConnectorPolicyMiddleware.
        # If ConnectorPolicyMiddleware didn't run (test setup, manifest
        # has no capabilities), bail out — we have nothing to validate
        # against.
        capability_id = ctx.metadata.get(CAPABILITY_ID_KEY)
        if not isinstance(capability_id, str):
            logger.debug(
                "OCSF normalizer skipped for %r: no capability id in context "
                "(ConnectorPolicyMiddleware did not run before this node).",
                manifest.name,
            )
            return
        capability = manifest.capability(capability_id)
        if capability is None:
            logger.debug(
                "OCSF normalizer skipped: capability %r not found on manifest %r.",
                capability_id,
                manifest.name,
            )
            return

        declared = list(capability.ocsf_emits)

        # If the capability declares no OCSF classes at all, the
        # contract is "raw vendor data, caller transforms" — skip
        # validation.
        if not declared:
            return

        raw_claims = _extract_ocsf_claims(output)
        observed: list[OCSFEventClass] = []
        undeclared_seen: list[str] = []
        for claim in raw_claims:
            parsed = _parse(claim)
            if parsed is None:
                undeclared_seen.append(claim)
                continue
            if parsed not in declared:
                undeclared_seen.append(claim)
                continue
            observed.append(parsed)

        summary = OCSFEmitSummary(
            connector=ctx.metadata.get(MANIFEST_NAME_KEY, "") or manifest.name,
            capability=capability_id,
            declared=declared,
            observed=list(dict.fromkeys(observed)),
            undeclared_seen=undeclared_seen,
        )
        ctx.metadata[OCSF_SUMMARY_KEY] = summary.model_dump()

        if undeclared_seen:
            raise OCSFContractViolation(
                f"Connector {manifest.name!r} capability {capability_id!r} "
                f"emitted OCSF class(es) {undeclared_seen!r} not in its declared "
                f"set {[c.value for c in declared]!r}. Update the manifest or "
                "fix the connector to match its contract."
            )


__all__ = [
    "OCSF_SUMMARY_KEY",
    "OCSFContractViolation",
    "OCSFEmitSummary",
    "OCSFNormalizerMiddleware",
]
