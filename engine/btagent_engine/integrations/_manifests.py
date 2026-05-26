"""Connector manifests for the built-in MCP integration nodes (#100 Phase 4).

Centralises the :class:`ConnectorManifest` for each shipped connector so
the integration node files attach a manifest with a one-line import
rather than repeating the capability tables inline. VirusTotal keeps its
manifest inline (it was the Phase-0 pattern proof); everything else
lives here.

TLP-egress rationale:
  * On-prem SIEM/EDR (Splunk, Sentinel, Elastic, CrowdStrike) declare
    ``tlp_egress=RED`` — the data never leaves the enclave, so the
    capability may run at any classification.
  * Cloud CTI (Shodan, GreyNoise, AbuseIPDB) declare ``tlp_egress=AMBER``
    — they egress an indicator to a third party, so they're blocked when
    the active context is AMBER_STRICT or RED.
  * MISP declares ``tlp_egress=AMBER_STRICT`` — typically self-hosted but
    treated as org-internal CTI.

``count_only_supported=True`` on the SIEM searches feeds the
NoiseBaseline node (#99 UC-4.1).
"""

from __future__ import annotations

from btagent_shared.types.config import TLP
from btagent_shared.types.connector import (
    ActionCapability,
    BlastRadius,
    ConnectorManifest,
    CostClass,
    CredentialType,
    OCSFEventClass,
    QueryCapability,
    TransportKind,
)

SPLUNK_MANIFEST = ConnectorManifest(
    name="splunk",
    version="0.1.0",
    description="Splunk Enterprise/Cloud — SPL search over indexed telemetry.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.BEARER,
    queries=[
        QueryCapability(
            id="search",
            description="Run an SPL search and return matching events.",
            ocsf_emits=[OCSFEventClass.NETWORK_ACTIVITY],
            tlp_egress=TLP.RED,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            count_only_supported=True,
        ),
    ],
)

SENTINEL_MANIFEST = ConnectorManifest(
    name="sentinel",
    version="0.1.0",
    description="Microsoft Sentinel — KQL query over Log Analytics workspaces.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.OAUTH2,
    queries=[
        QueryCapability(
            id="kql_query",
            description="Run a KQL query and return matching records.",
            ocsf_emits=[OCSFEventClass.AUTHENTICATION, OCSFEventClass.NETWORK_ACTIVITY],
            tlp_egress=TLP.RED,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            count_only_supported=True,
        ),
    ],
)

ELASTIC_MANIFEST = ConnectorManifest(
    name="elastic",
    version="0.1.0",
    description="Elastic Security — ES|QL / DSL search over indices.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="search",
            description="Run an Elastic search and return matching documents.",
            ocsf_emits=[OCSFEventClass.NETWORK_ACTIVITY],
            tlp_egress=TLP.RED,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
            count_only_supported=True,
        ),
    ],
)

CROWDSTRIKE_MANIFEST = ConnectorManifest(
    name="crowdstrike",
    version="0.1.0",
    description="CrowdStrike Falcon — detections query + host containment.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.CUSTOM,  # client id + secret pair
    queries=[
        QueryCapability(
            id="list_detections",
            description="List Falcon detections matching a filter.",
            ocsf_emits=[OCSFEventClass.DETECTION_FINDING],
            tlp_egress=TLP.RED,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
            count_only_supported=True,
        ),
    ],
    actions=[
        ActionCapability(
            id="isolate_host",
            description="Network-contain a host via Falcon RTR.",
            ocsf_emits=[OCSFEventClass.DEVICE_CONFIG_STATE],
            tlp_egress=TLP.RED,
            cost_class=CostClass.EXPENSIVE,
            hitl_required=True,  # mutate action — adaptive consent
            reversible=True,  # host can be un-isolated
            blast_radius=BlastRadius.SINGLE_HOST,
        ),
    ],
)

SHODAN_MANIFEST = ConnectorManifest(
    name="shodan",
    version="0.1.0",
    description="Shodan — internet-exposure host lookup.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="host_lookup",
            description="Look up exposure / banner data for an IP.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.MODERATE,
            hitl_required=False,
        ),
    ],
)

GREYNOISE_MANIFEST = ConnectorManifest(
    name="greynoise",
    version="0.1.0",
    description="GreyNoise — internet-background-noise classification for an IP.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="lookup_ip",
            description="Classify an IP as benign/malicious/unknown noise.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
        ),
    ],
)

ABUSEIPDB_MANIFEST = ConnectorManifest(
    name="abuseipdb",
    version="0.1.0",
    description="AbuseIPDB — community abuse-confidence score for an IP.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="check",
            description="Return abuse-confidence score + report categories for an IP.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
        ),
    ],
)

MISP_MANIFEST = ConnectorManifest(
    name="misp",
    version="0.1.0",
    description="MISP — threat-intel attribute search + event retrieval.",
    transport=TransportKind.HTTP_REST,
    auth=CredentialType.API_KEY,
    queries=[
        QueryCapability(
            id="search_attribute",
            description="Search MISP attributes for an indicator.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER_STRICT,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
        ),
        QueryCapability(
            id="get_event",
            description="Fetch a full MISP event by id.",
            ocsf_emits=[OCSFEventClass.THREAT_INTELLIGENCE],
            tlp_egress=TLP.AMBER_STRICT,
            cost_class=CostClass.CHEAP,
            hitl_required=False,
        ),
    ],
)


__all__ = [
    "ABUSEIPDB_MANIFEST",
    "CROWDSTRIKE_MANIFEST",
    "ELASTIC_MANIFEST",
    "GREYNOISE_MANIFEST",
    "MISP_MANIFEST",
    "SENTINEL_MANIFEST",
    "SHODAN_MANIFEST",
    "SPLUNK_MANIFEST",
]
