"""Centralised TLP enforcement — exception type plus egress gate.

Provides:

* :class:`TLPViolation` -- raised by every TLP gate (LLM-call provider check
  in ``btagent_agents.hooks.classification_hook`` and the four non-LLM egress
  gates below). A single ``except TLPViolation:`` covers both.
* :func:`assert_tlp_allows_egress` -- the gate that all non-LLM egress points
  must call before letting tagged data leave the originating investigation
  context.

Egress kinds covered:

* ``"stix_export"``      - STIX 2.1 bundle generation / export
* ``"knowledge_ingest"`` - RAG knowledge-base document ingestion
* ``"mcp_return"``       - MCP tool-call return envelopes
* ``"event_emit"``       - WebSocket / Redis event broadcast
* ``"report_export"``    - rendered report export (e.g. PDF download)

Behaviour:

* TLP:RED is *blocked* on every egress kind. The function raises
  :class:`TLPViolation`.
* TLP:AMBER_STRICT and below are *allowed*; AMBER_STRICT triggers a logged
  warning so operators can audit which channels are carrying restricted data.
* Unknown / missing classification is treated as TLP:GREEN -- matching the
  default in :class:`btagent_shared.types.config.AgentConfig`.

The helper is small and synchronous so it can be invoked from anywhere --
sync code, async coroutines, hooks, services -- without adding a new
dependency on the event loop.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from btagent_shared.types.config import TLP

logger = logging.getLogger("btagent.security.tlp")


class TLPViolation(Exception):
    """Raised when TLP-classified data would cross a forbidden boundary.

    Carries the offending TLP level and the channel name (``provider`` for
    the LLM-call gate, ``"egress:<kind>"`` for the egress gate) so handlers
    can audit-log uniformly.
    """

    def __init__(self, tlp: TLP, channel: str) -> None:
        self.tlp = tlp
        # Kept as ``provider`` for backwards compatibility with the original
        # classification_hook gate; new call sites should treat it as the
        # generic channel identifier.
        self.provider = channel
        super().__init__(f"TLP:{tlp.value.upper()} data cannot be sent to channel {channel!r}")


EgressKind = Literal[
    "stix_export",
    "knowledge_ingest",
    "mcp_return",
    "event_emit",
    "report_export",
]

_VALID_EGRESS_KINDS: frozenset[str] = frozenset(
    {"stix_export", "knowledge_ingest", "mcp_return", "event_emit", "report_export"}
)

# Field names searched on payloads to discover an embedded TLP tag. We accept
# both ``tlp`` and ``tlp_level`` and look at top-level keys plus a single
# nested ``metadata`` mapping -- which is where MCP connectors and STIX
# converters tend to put it.
_TLP_FIELD_NAMES: tuple[str, ...] = ("tlp_level", "tlp", "TLP", "TLPLevel")


def _coerce_tlp(value: Any) -> TLP | None:
    if value is None:
        return None
    if isinstance(value, TLP):
        return value
    if isinstance(value, str):
        try:
            return TLP(value.lower())
        except ValueError:
            return None
    return None


def _scan_payload_for_red(payload: Any) -> bool:
    return _scan(payload, depth=0)


def _scan(node: Any, *, depth: int) -> bool:
    if depth > 8:
        return False
    if isinstance(node, dict):
        for key in _TLP_FIELD_NAMES:
            if key in node and _coerce_tlp(node[key]) == TLP.RED:
                return True
        for value in node.values():
            if _scan(value, depth=depth + 1):
                return True
        return False
    if isinstance(node, list | tuple):
        for item in node:
            if _scan(item, depth=depth + 1):
                return True
    return False


def _resolve_classification(
    classification_ctx: TLP | str | dict[str, Any] | None,
) -> TLP:
    if isinstance(classification_ctx, TLP):
        return classification_ctx
    if isinstance(classification_ctx, str):
        coerced = _coerce_tlp(classification_ctx)
        return coerced if coerced is not None else TLP.GREEN
    if isinstance(classification_ctx, dict):
        for key in _TLP_FIELD_NAMES:
            if key in classification_ctx:
                coerced = _coerce_tlp(classification_ctx[key])
                if coerced is not None:
                    return coerced
    return TLP.GREEN


def _emit_block_event(egress_kind: str, org_id: str | None, reason: str) -> None:
    """Fire a ``tlp.violation_attempt`` event for a refused egress.

    Imported lazily so ``tlp`` carries no import-time dependency on the
    policy module, and best-effort so alerting can never break the gate.
    """
    from btagent_shared.security.tlp_policy import TLPViolationEvent, emit_violation

    emit_violation(
        TLPViolationEvent(
            tlp=TLP.RED,
            egress_kind=egress_kind,
            channel=f"egress:{egress_kind}",
            org_id=org_id,
            reason=reason,
        )
    )


def assert_tlp_allows_egress(
    payload: Any,
    egress_kind: EgressKind | str,
    classification_ctx: TLP | str | dict[str, Any] | None = None,
    *,
    org_id: str | None = None,
) -> None:
    """Block egress of TLP:RED data; warn on TLP:AMBER_STRICT.

    Parameters
    ----------
    payload:
        The data about to leave the investigation. Walked recursively to
        detect any embedded ``tlp`` / ``tlp_level`` field set to ``"red"``.
    egress_kind:
        One of the four :data:`EgressKind` values.
    classification_ctx:
        The investigation-wide classification (typically
        :attr:`AgentConfig.tlp_level`). May also be a string (``"red"``,
        ``"amber"``, ...) or a mapping containing a TLP field. ``None``
        defaults to :attr:`TLP.GREEN`.
    org_id:
        Optional org identifier carried on the emitted
        ``tlp.violation_attempt`` event so the alerter can route by tenant.

    Raises
    ------
    TLPViolation:
        If the resolved context is :attr:`TLP.RED`, *or* the payload
        contains any item explicitly tagged TLP:RED. A
        ``tlp.violation_attempt`` event is emitted (best-effort) before the
        exception is raised.
    ValueError:
        If *egress_kind* is not one of the recognised values. Egress sites
        must opt into a known channel name -- silent fall-throughs would
        defeat the purpose of central enforcement.
    """
    if egress_kind not in _VALID_EGRESS_KINDS:
        raise ValueError(
            f"Unknown egress_kind {egress_kind!r}; expected one of {sorted(_VALID_EGRESS_KINDS)}"
        )

    ctx_tlp = _resolve_classification(classification_ctx)

    if ctx_tlp == TLP.RED:
        logger.error(
            "TLP egress block: investigation classification is TLP:RED; refusing egress via %s",
            egress_kind,
        )
        _emit_block_event(egress_kind, org_id, "investigation classification is TLP:RED")
        raise TLPViolation(TLP.RED, f"egress:{egress_kind}")

    if _scan_payload_for_red(payload):
        logger.error(
            "TLP egress block: payload contains TLP:RED-tagged data; refusing egress via %s",
            egress_kind,
        )
        _emit_block_event(egress_kind, org_id, "payload contains TLP:RED-tagged data")
        raise TLPViolation(TLP.RED, f"egress:{egress_kind}")

    if ctx_tlp == TLP.AMBER_STRICT:
        logger.warning(
            "TLP:AMBER_STRICT data permitted to egress via %s (allowed but auditable)",
            egress_kind,
        )


__all__ = [
    "EgressKind",
    "TLPViolation",
    "assert_tlp_allows_egress",
]
