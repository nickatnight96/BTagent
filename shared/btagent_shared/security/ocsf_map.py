"""Per-connector field → OCSF normalization maps (UC-1.2, #104).

The "governed semantic layer" from the catalog: declares how each
connector's vendor-specific event shape maps onto the canonical
OCSF-aligned :class:`NormalizedEvent`. Deliberately lives *outside* the
connector manifest (which owns capabilities/policy, #100) so the
manifest stays lean — this is the complementary "how to reshape into
the declared OCSF class" data.

Pure data + pydantic only. The engine's ``OCSFMapperNode`` reads these;
backend services can introspect them too (e.g. to render a
field-coverage view).

Field paths support dotted notation for nested vendor shapes
(Elastic's ``source.ip``); the mapper resolves them with a dotted-get.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.connector import OCSFEventClass


class OCSFFieldMap(BaseModel):
    """How one connector's raw event maps to canonical NormalizedEvent fields."""

    model_config = ConfigDict(extra="forbid")

    connector: str
    ocsf_event_class: OCSFEventClass
    timestamp_field: str = Field(
        ..., description="Vendor field holding the event time (dotted path ok)."
    )
    # canonical field name -> vendor field path(s). First present wins.
    field_renames: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Canonical NormalizedEvent field -> ordered list of vendor "
        "paths to try (handles src_ip vs source.ip across vendors).",
    )
    action_field: str | None = Field(
        default=None, description="Vendor field holding the action verb, if any."
    )
    summary_template: str = Field(
        default="",
        description="Optional str.format template over canonical fields for the "
        "timeline row, e.g. '{source_ip} -> {dest_ip} ({action})'.",
    )


# ---------------------------------------------------------------------------
# The maps. One per connector we can correlate today. Add entries as the
# connector catalog grows (#100 Phase 4 retrofit).
# ---------------------------------------------------------------------------

OCSF_MAPS: dict[str, OCSFFieldMap] = {
    "splunk": OCSFFieldMap(
        connector="splunk",
        ocsf_event_class=OCSFEventClass.NETWORK_ACTIVITY,
        timestamp_field="_time",
        field_renames={
            "source_ip": ["src_ip", "src"],
            "dest_ip": ["dest_ip", "dest"],
            "user": ["user", "user_name"],
            "host": ["host", "dvc"],
            "domain": ["query", "dns_query"],
        },
        action_field="action",
        summary_template="{source_ip} -> {dest_ip} ({action})",
    ),
    "elastic": OCSFFieldMap(
        connector="elastic",
        ocsf_event_class=OCSFEventClass.NETWORK_ACTIVITY,
        timestamp_field="@timestamp",
        field_renames={
            "source_ip": ["source.ip"],
            "dest_ip": ["destination.ip"],
            "user": ["user.name"],
            "host": ["host.name"],
            "domain": ["dns.question.name"],
        },
        action_field="event.action",
        summary_template="{source_ip} -> {dest_ip} ({action})",
    ),
    "sentinel": OCSFFieldMap(
        connector="sentinel",
        ocsf_event_class=OCSFEventClass.AUTHENTICATION,
        timestamp_field="TimeGenerated",
        field_renames={
            "source_ip": ["IpAddress", "SrcIpAddr"],
            "dest_ip": ["DstIpAddr"],
            "user": ["AccountUpn", "Account"],
            "host": ["Computer", "DeviceName"],
        },
        action_field="ResultType",
        summary_template="{user} from {source_ip} ({action})",
    ),
    "crowdstrike": OCSFFieldMap(
        connector="crowdstrike",
        ocsf_event_class=OCSFEventClass.PROCESS_ACTIVITY,
        timestamp_field="timestamp",
        field_renames={
            "source_ip": ["LocalAddressIP4", "RemoteAddressIP4"],
            "user": ["UserName"],
            "host": ["ComputerName", "aid"],
            "file_hash": ["SHA256HashData", "MD5HashData"],
        },
        action_field="event_simpleName",
        summary_template="{host}: {action} ({file_hash})",
    ),
    # Firewall (Palo Alto-ish) — emitted via Splunk index in many shops but
    # modelled separately for VPC/flow correlation.
    "firewall": OCSFFieldMap(
        connector="firewall",
        ocsf_event_class=OCSFEventClass.NETWORK_ACTIVITY,
        timestamp_field="receive_time",
        field_renames={
            "source_ip": ["src", "source_ip"],
            "dest_ip": ["dst", "dest_ip"],
            "action": ["action"],
        },
        action_field="action",
        summary_template="{source_ip} -> {dest_ip} ({action})",
    ),
}


def get_map(connector: str) -> OCSFFieldMap | None:
    """Return the OCSF field map for a connector, or None if unmapped."""
    return OCSF_MAPS.get(connector)


__all__ = ["OCSF_MAPS", "OCSFFieldMap", "get_map"]
