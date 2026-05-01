"""Centralized TLP egress enforcement.

Provides a single function -- :func:`assert_tlp_allows_egress` -- that all
non-LLM egress points must call before letting tagged data leave the
originating investigation context. The LLM-call gate is handled separately by
:mod:`btagent_agents.hooks.classification_hook`; the four call sites covered
here are:

* ``"stix_export"``      - STIX 2.1 bundle generation / export
* ``"knowledge_ingest"`` - RAG knowledge-base document ingestion
* ``"mcp_return"``       - MCP tool-call return envelopes
* ``"event_emit"``       - WebSocket / Redis event broadcast

Behaviour summary
-----------------
* TLP:RED is *blocked* on every egress kind. The function raises
  :class:`TLPViolation` (re-exported from :mod:`classification_hook` so call
  sites have a single exception type to catch).
* TLP:AMBER_STRICT and below are *allowed*; AMBER_STRICT triggers a logged
  warning so that operators can audit which channels are carrying restricted
  data.
* Unknown / missing classification is treated as TLP:GREEN (the documented
  default in :class:`btagent_shared.types.config.AgentConfig`).

The helper is deliberately small and synchronous so it can be invoked from
anywhere -- sync code, async coroutines, hooks, services -- without adding a
new dependency on the event loop.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from btagent_shared.types.config import TLP

from btagent_agents.hooks.classification_hook import TLPViolation

logger = logging.getLogger("btagent.hooks.tlp_egress")

EgressKind = Literal[
    "stix_export",
    "knowledge_ingest",
    "mcp_return",
    "event_emit",
]

_VALID_EGRESS_KINDS: frozenset[str] = frozenset(
    {"stix_export", "knowledge_ingest", "mcp_return", "event_emit"}
)

# Field names searched on payloads to discover an embedded TLP tag. We accept
# both ``tlp`` and ``tlp_level`` and look at top-level keys plus a single
# nested ``metadata`` mapping -- which is where MCP connectors and STIX
# converters tend to put it.
_TLP_FIELD_NAMES: tuple[str, ...] = ("tlp_level", "tlp", "TLP", "TLPLevel")


def _coerce_tlp(value: Any) -> TLP | None:
    """Best-effort conversion of *value* to a :class:`TLP` member."""
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
    """Return ``True`` if *payload* contains any TLP:RED-tagged item.

    Walks dicts and lists up to a reasonable depth. Strings, numbers, and
    other scalar types are ignored -- they cannot carry their own TLP tag.
    """
    return _scan(payload, depth=0)


def _scan(node: Any, *, depth: int) -> bool:
    if depth > 8:
        # Defensive: stop recursing into pathological structures.
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
    """Normalise the classification context into a TLP enum value.

    ``None`` and unrecognised values default to :attr:`TLP.GREEN` -- matching
    the default in :class:`AgentConfig`. Callers that want strict behaviour
    should always pass an explicit TLP.
    """
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


def assert_tlp_allows_egress(
    payload: Any,
    egress_kind: EgressKind | str,
    classification_ctx: TLP | str | dict[str, Any] | None = None,
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

    Raises
    ------
    TLPViolation:
        If the resolved context is :attr:`TLP.RED`, *or* the payload contains
        any item explicitly tagged TLP:RED. The exception is the same type
        raised by :class:`ClassificationCallback` so a single
        ``except TLPViolation:`` handler covers both gates.
    ValueError:
        If *egress_kind* is not one of the recognised values. Egress sites
        must opt into a known channel name -- silent fall-throughs would
        defeat the purpose of central enforcement.
    """
    if egress_kind not in _VALID_EGRESS_KINDS:
        raise ValueError(
            f"Unknown egress_kind {egress_kind!r}; expected one of "
            f"{sorted(_VALID_EGRESS_KINDS)}"
        )

    ctx_tlp = _resolve_classification(classification_ctx)

    # Hard block: investigation is RED -> nothing leaves, regardless of payload.
    if ctx_tlp == TLP.RED:
        logger.error(
            "TLP egress block: investigation classification is TLP:RED; "
            "refusing egress via %s",
            egress_kind,
        )
        raise TLPViolation(TLP.RED, f"egress:{egress_kind}")

    # Hard block: any RED-tagged item inside the payload itself.
    if _scan_payload_for_red(payload):
        logger.error(
            "TLP egress block: payload contains TLP:RED-tagged data; "
            "refusing egress via %s",
            egress_kind,
        )
        raise TLPViolation(TLP.RED, f"egress:{egress_kind}")

    # Soft warn for AMBER_STRICT so operators can audit restricted channels.
    if ctx_tlp == TLP.AMBER_STRICT:
        logger.warning(
            "TLP:AMBER_STRICT data permitted to egress via %s "
            "(allowed but auditable)",
            egress_kind,
        )


__all__ = [
    "EgressKind",
    "TLPViolation",
    "assert_tlp_allows_egress",
]
