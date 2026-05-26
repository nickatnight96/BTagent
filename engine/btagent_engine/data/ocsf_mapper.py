"""OCSFMapperNode — vendor event shape -> canonical NormalizedEvent (UC-1.2).

The "governed semantic layer" executor. Takes a connector name + a list
of raw vendor events and applies the connector's
:class:`btagent_shared.security.ocsf_map.OCSFFieldMap`:

* resolves dotted vendor paths (Elastic ``source.ip``) and flat ones
  (Splunk ``src_ip``) to the same canonical ``source_ip``;
* parses the vendor timestamp to tz-aware UTC;
* attaches the declared OCSF event class;
* preserves the raw event + a lineage ref.

Pure data transform — no LLM, no network, no mock branch. Deterministic
by construction, so it needs no ``BTAGENT_MOCK_*`` gate.

Note on TransformNode: the existing ``TransformNode`` only handles flat
keys (rename/drop/set/keep_only). Elastic events are nested
(``source.ip``), so this node carries its own dotted-path getter rather
than forcing TransformNode to grow nested support.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.security.ocsf_map import get_map
from btagent_shared.types.correlation import NormalizedEvent, RawEventRef

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


class UnknownConnectorError(ValueError):
    """No OCSF field map exists for the requested connector.

    Fail loud rather than silently emitting un-normalized events — an
    unmapped connector means the correlation timeline would carry
    vendor-shaped rows that break downstream field access.
    """


def _dotted_get(d: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path against a (possibly nested) dict.

    ``_dotted_get({"source": {"ip": "1.2.3.4"}}, "source.ip") -> "1.2.3.4"``
    ``_dotted_get({"src_ip": "1.2.3.4"}, "src_ip") -> "1.2.3.4"``
    Returns None if any segment is missing.
    """
    cur: Any = d
    for seg in path.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return None
        cur = cur[seg]
    return cur


def _first_present(event: dict[str, Any], paths: list[str]) -> Any:
    """First non-None value across an ordered list of candidate paths."""
    for p in paths:
        val = _dotted_get(event, p)
        if val is not None:
            return val
    return None


def _to_utc(value: Any) -> datetime:
    """Best-effort parse of a vendor timestamp into tz-aware UTC.

    Accepts:
      * datetime (naive -> assumed UTC; aware -> converted)
      * ISO-8601 strings, incl. trailing 'Z' and offsets
      * epoch seconds (int/float or numeric string)
    Falls back to ``datetime.now(UTC)`` on an unparseable value rather
    than raising — a correlation timeline with a slightly-wrong
    timestamp is more useful than a hard failure on one bad event.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    if isinstance(value, str):
        s = value.strip()
        # epoch-as-string
        try:
            return datetime.fromtimestamp(float(s), tz=timezone.utc)
        except (ValueError, OverflowError):
            pass
        # ISO-8601 (handle trailing Z)
        try:
            iso = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


def _event_id(connector: str, locator: str, idx: int) -> str:
    seed = f"{connector}:{locator}:{idx}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:16]


class OCSFMapperInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector: str = Field(..., description="Connector name; must have an OCSF_MAPS entry.")
    raw_events: list[dict[str, Any]] = Field(
        default_factory=list, description="Raw vendor events to normalize."
    )
    capability_id: str = Field(
        default="", description="Capability the events came from (for lineage)."
    )


class OCSFMapperOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[NormalizedEvent] = Field(default_factory=list)


class OCSFMapperNode(Node[OCSFMapperInput, OCSFMapperOutput]):
    """Normalize a connector's raw events into canonical NormalizedEvents."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.ocsf_mapper",
        name="OCSF Mapper",
        version="0.1.0",
        category=NodeCategory.DATA,
        description=(
            "Normalize vendor-specific event shapes into canonical "
            "OCSF-aligned NormalizedEvents (field renames + UTC timestamps "
            "+ lineage refs) via the governed semantic layer."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = OCSFMapperInput
    output_schema: ClassVar[type[BaseModel]] = OCSFMapperOutput

    async def run(
        self,
        input: OCSFMapperInput,
        ctx: NodeContext,
    ) -> OCSFMapperOutput:
        fmap = get_map(input.connector)
        if fmap is None:
            raise UnknownConnectorError(
                f"No OCSF field map for connector {input.connector!r}. "
                "Add an entry to btagent_shared.security.ocsf_map.OCSF_MAPS."
            )

        out: list[NormalizedEvent] = []
        for idx, raw in enumerate(input.raw_events):
            canonical: dict[str, Any] = {}
            for canon_field, vendor_paths in fmap.field_renames.items():
                val = _first_present(raw, vendor_paths)
                if val is not None:
                    canonical[canon_field] = str(val)

            action = None
            if fmap.action_field is not None:
                av = _dotted_get(raw, fmap.action_field)
                action = str(av) if av is not None else None

            ts = _to_utc(_dotted_get(raw, fmap.timestamp_field))
            locator = str(
                _dotted_get(raw, "_id")
                or _dotted_get(raw, "_cd")
                or _dotted_get(raw, "event_id")
                or idx
            )

            summary = ""
            if fmap.summary_template:
                # Defensive format — missing keys render as empty rather
                # than raising KeyError on a sparse event.
                summary = fmap.summary_template.format_map(
                    _DefaultDict(canonical | ({"action": action} if action else {}))
                )

            out.append(
                NormalizedEvent(
                    event_id=_event_id(input.connector, locator, idx),
                    timestamp=ts,
                    source_connector=input.connector,
                    ocsf_event_class=fmap.ocsf_event_class,
                    source_ip=canonical.get("source_ip"),
                    dest_ip=canonical.get("dest_ip"),
                    user=canonical.get("user"),
                    host=canonical.get("host"),
                    file_hash=canonical.get("file_hash"),
                    domain=canonical.get("domain"),
                    action=action,
                    summary=summary,
                    raw_ref=RawEventRef(
                        connector=input.connector,
                        capability_id=input.capability_id,
                        locator=locator,
                        queried_at=datetime.now(timezone.utc),
                    ),
                    raw_event=raw,
                )
            )
        return OCSFMapperOutput(events=out)


class _DefaultDict(dict):
    """format_map helper: missing keys render as empty string."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        return ""


NodeRegistry.register(OCSFMapperNode)


__all__ = [
    "OCSFMapperInput",
    "OCSFMapperNode",
    "OCSFMapperOutput",
    "UnknownConnectorError",
]
