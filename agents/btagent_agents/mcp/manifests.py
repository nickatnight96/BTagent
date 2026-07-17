"""Capability manifests for every registered MCP server (#100 Layer 3).

The engine's Phase-4 manifest layer covered its integration *nodes*
(:mod:`btagent_engine.integrations._manifests`); this module is the same
layer for the agents-side **MCP server registry** — one
:class:`~btagent_shared.types.connector.ConnectorManifest` per
``discovery._SERVER_CLASSES`` entry, keyed by ``server_id``.

Conventions (pinned by ``agents/tests/test_mcp_server_manifests.py``):

* **Capability id == MCP tool name.** MCP tools are already globally
  unique, stable identifiers (``mde_isolate_machine``), so the manifest
  reuses them verbatim — the drift test asserts the manifest's ids and
  the server's ``get_tool_metadata()`` names are equal sets, which is
  what catches a connector growing a tool without declaring its policy.
* **TLP egress follows the engine precedent**: on-prem / in-enclave
  telemetry (Splunk, Sentinel, Elastic, CrowdStrike, Zeek) declares
  ``TLP.RED``; org-tenant clouds (IdPs, M365/MDE, SentinelOne console,
  AWS, Jira, Slack, Git) declare ``TLP.AMBER_STRICT``.
* **Every mutating tool is an ActionCapability.** Containment actions
  (``cs_isolate_host``, ``mde_isolate_machine``, ``s1_mitigate_threat``)
  and the detection-repo PR composer keep ``hitl_required=True``.
  Collaboration-sink writes (Jira tickets/comments/transitions, Slack
  channels/messages/pins) opt out of HITL — they have no enforcement
  effect on the environment (``BlastRadius.NONE``) and are the whole
  point of automated sinks; a deployment can still re-gate them.
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

_O = OCSFEventClass  # local alias to keep the capability tables readable


def _query(
    tool: str,
    description: str,
    emits: list[OCSFEventClass],
    *,
    tlp: TLP,
    cost: CostClass = CostClass.CHEAP,
) -> QueryCapability:
    return QueryCapability(
        id=tool, description=description, ocsf_emits=emits, tlp_egress=tlp, cost_class=cost
    )


MANIFESTS: dict[str, ConnectorManifest] = {
    # ------------------------------------------------------------------ #
    # Phase-1 SIEM / EDR (on-prem enclave -> TLP.RED, engine precedent)
    # ------------------------------------------------------------------ #
    "splunk": ConnectorManifest(
        name="splunk",
        version="0.1.0",
        description="Splunk Enterprise Security — SPL search, alerts, notables.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BEARER,
        queries=[
            _query(
                "splunk_search",
                "Run an SPL search over indexed telemetry.",
                [_O.NETWORK_ACTIVITY],
                tlp=TLP.RED,
                cost=CostClass.MODERATE,
            ),
            _query("splunk_get_alerts", "List fired alerts.", [_O.DETECTION_FINDING], tlp=TLP.RED),
            _query(
                "splunk_get_notable",
                "List ES notable events.",
                [_O.DETECTION_FINDING],
                tlp=TLP.RED,
            ),
        ],
    ),
    "crowdstrike": ConnectorManifest(
        name="crowdstrike",
        version="0.1.0",
        description="CrowdStrike Falcon — detections, host details, containment.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.CUSTOM,
        queries=[
            _query(
                "cs_get_detections",
                "Detections with behaviors + MITRE mappings.",
                [_O.DETECTION_FINDING],
                tlp=TLP.RED,
            ),
            _query("cs_host_details", "Host record lookup.", [_O.DEVICE_INVENTORY], tlp=TLP.RED),
            _query(
                "cs_search_events",
                "Event telemetry search.",
                [_O.PROCESS_ACTIVITY, _O.NETWORK_ACTIVITY, _O.DNS_ACTIVITY],
                tlp=TLP.RED,
                cost=CostClass.MODERATE,
            ),
        ],
        actions=[
            ActionCapability(
                id="cs_isolate_host",
                description="Network-contain a host (Falcon agent stays reachable).",
                tlp_egress=TLP.RED,
                cost_class=CostClass.EXPENSIVE,
                hitl_required=True,
                reversible=True,
                blast_radius=BlastRadius.SINGLE_HOST,
            ),
        ],
    ),
    "sentinel": ConnectorManifest(
        name="sentinel",
        version="0.1.0",
        description="Microsoft Sentinel — KQL, incidents, alerts.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.OAUTH2,
        queries=[
            _query(
                "sentinel_query",
                "Run a KQL query over Log Analytics.",
                [_O.AUTHENTICATION, _O.NETWORK_ACTIVITY],
                tlp=TLP.RED,
                cost=CostClass.MODERATE,
            ),
            _query(
                "sentinel_get_incidents",
                "List Sentinel incidents.",
                [_O.INCIDENT_FINDING],
                tlp=TLP.RED,
            ),
            _query(
                "sentinel_get_alerts", "List Sentinel alerts.", [_O.DETECTION_FINDING], tlp=TLP.RED
            ),
        ],
    ),
    "elastic": ConnectorManifest(
        name="elastic",
        version="0.1.0",
        description="Elastic Security — DSL search, alerts, field discovery.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.API_KEY,
        queries=[
            _query(
                "elastic_search",
                "Search security indices.",
                [_O.NETWORK_ACTIVITY],
                tlp=TLP.RED,
                cost=CostClass.MODERATE,
            ),
            _query(
                "elastic_get_alerts",
                "List detection-engine alerts.",
                [_O.DETECTION_FINDING],
                tlp=TLP.RED,
            ),
            _query("elastic_get_fields", "Discover index field mappings.", [], tlp=TLP.RED),
        ],
    ),
    # ------------------------------------------------------------------ #
    # Tier-1 identity (org-tenant IdPs -> TLP.AMBER_STRICT)
    # ------------------------------------------------------------------ #
    "okta": ConnectorManifest(
        name="okta",
        version="0.1.0",
        description="Okta — System Log, OAuth grants, sessions.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.API_KEY,
        queries=[
            _query(
                "okta_system_log_search",
                "System Log events (logins, MFA, grants).",
                [_O.AUTHENTICATION, _O.AUDIT_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "okta_list_oauth_grants",
                "Per-user OAuth grants.",
                [_O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "okta_list_sessions",
                "Active sessions per user.",
                [_O.AUTHORIZE_SESSION],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "entra": ConnectorManifest(
        name="entra",
        version="0.1.0",
        description="Microsoft Entra ID — sign-ins, audit, OAuth grants.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.OAUTH2,
        queries=[
            _query(
                "entra_signin_log_search",
                "Sign-in log events.",
                [_O.AUTHENTICATION],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "entra_audit_log_search",
                "Directory audit events (roles, consent, federation).",
                [_O.AUDIT_ACTIVITY, _O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "entra_list_oauth_grants",
                "Service-principal / delegated grants.",
                [_O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "gws": ConnectorManifest(
        name="gws",
        version="0.1.0",
        description="Google Workspace — login/admin/token activity, OAuth tokens.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.JWT,
        queries=[
            _query(
                "gws_login_activity_search",
                "Login-application activity (2SV, failures).",
                [_O.AUTHENTICATION],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "gws_audit_activity_search",
                "Admin + token application activity.",
                [_O.AUDIT_ACTIVITY, _O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "gws_list_oauth_tokens",
                "Per-user Directory OAuth tokens.",
                [_O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    # Tier-2 identity MFA (cloud MFA -> TLP.AMBER_STRICT).
    "duo": ConnectorManifest(
        name="duo",
        version="0.1.0",
        description="Cisco Duo MFA — auth logs, users, admin activity.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.CUSTOM,
        queries=[
            _query(
                "duo_auth_log_search",
                "Authentication logs (MFA approve/deny/fraud).",
                [_O.AUTHENTICATION],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "duo_list_users",
                "Enrolled users (status, phones, bypass-code count).",
                [_O.USER_INVENTORY],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "duo_admin_log_search",
                "Administrator activity (bypass/admin/policy changes).",
                [_O.AUDIT_ACTIVITY, _O.ENTITY_MANAGEMENT],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "cortex": ConnectorManifest(
        name="cortex",
        version="0.1.0",
        description="Palo Alto Cortex XDR — XQL, incidents, endpoints, isolation.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.API_KEY,
        queries=[
            _query(
                "cortex_xql_query",
                "XQL event search over endpoint telemetry.",
                [_O.PROCESS_ACTIVITY, _O.NETWORK_ACTIVITY, _O.DNS_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "cortex_list_incidents",
                "Incidents with severity + status lifecycle.",
                [_O.DETECTION_FINDING],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "cortex_get_endpoint",
                "Endpoint record (connection + isolation state).",
                [_O.DEVICE_INVENTORY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="cortex_isolate_endpoint",
                description="Network-isolate / unisolate an endpoint.",
                tlp_egress=TLP.AMBER_STRICT,
                cost_class=CostClass.EXPENSIVE,
                hitl_required=True,
                reversible=True,
                blast_radius=BlastRadius.SINGLE_HOST,
            ),
        ],
    ),
    # ------------------------------------------------------------------ #
    # Tier-1 email / EDR / network / cloud
    # ------------------------------------------------------------------ #
    "defender_o365": ConnectorManifest(
        name="defender_o365",
        version="0.1.0",
        description="Defender for Office 365 — email events, quarantine, submissions.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.OAUTH2,
        queries=[
            _query(
                "o365_email_events_search",
                "EmailEvents (verdicts + delivery outcomes).",
                [_O.EMAIL_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "o365_list_quarantine",
                "Quarantined messages + release lifecycle.",
                [_O.EMAIL_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "o365_list_threat_submissions",
                "User/admin threat submissions (triage intake).",
                [_O.EMAIL_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "defender_endpoint": ConnectorManifest(
        name="defender_endpoint",
        version="0.1.0",
        description="Defender for Endpoint — KQL hunting, alerts, isolation.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.OAUTH2,
        queries=[
            _query(
                "mde_advanced_hunting_query",
                "Advanced Hunting KQL over device telemetry.",
                [_O.PROCESS_ACTIVITY, _O.NETWORK_ACTIVITY, _O.AUTHENTICATION],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "mde_list_alerts",
                "alerts_v2 alert list.",
                [_O.DETECTION_FINDING],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "mde_get_machine",
                "Device record (risk / exposure / isolation state).",
                [_O.DEVICE_INVENTORY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="mde_isolate_machine",
                description="Selective/full network containment of a device.",
                tlp_egress=TLP.AMBER_STRICT,
                cost_class=CostClass.EXPENSIVE,
                hitl_required=True,
                reversible=True,
                blast_radius=BlastRadius.SINGLE_HOST,
            ),
        ],
    ),
    "sentinelone": ConnectorManifest(
        name="sentinelone",
        version="0.1.0",
        description="SentinelOne — Deep Visibility, threats, agents, mitigation.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.API_KEY,
        queries=[
            _query(
                "s1_deep_visibility_query",
                "S1QL event search over endpoint telemetry.",
                [_O.PROCESS_ACTIVITY, _O.NETWORK_ACTIVITY, _O.DNS_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "s1_list_threats",
                "Threats with mitigation lifecycle.",
                [_O.DETECTION_FINDING],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "s1_get_agent",
                "Agent record (infected flag, network status).",
                [_O.DEVICE_INVENTORY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="s1_mitigate_threat",
                description="kill / quarantine / remediate / rollback-remediation.",
                tlp_egress=TLP.AMBER_STRICT,
                cost_class=CostClass.EXPENSIVE,
                hitl_required=True,
                reversible=True,
                blast_radius=BlastRadius.SINGLE_HOST,
            ),
        ],
    ),
    "zeek": ConnectorManifest(
        name="zeek",
        version="0.1.0",
        description="Zeek / Corelight — log streams, notices, behavioral summary.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BEARER,
        queries=[
            _query(
                "zeek_log_search",
                "conn/dns/ssl/notice stream search.",
                [_O.NETWORK_ACTIVITY, _O.DNS_ACTIVITY, _O.HTTP_ACTIVITY],
                tlp=TLP.RED,
                cost=CostClass.MODERATE,
            ),
            _query(
                "zeek_list_notices", "notice.log detections.", [_O.DETECTION_FINDING], tlp=TLP.RED
            ),
            _query(
                "zeek_connection_summary",
                "Per-host behavioral rollup (beacon/exfil signal).",
                [_O.NETWORK_ACTIVITY],
                tlp=TLP.RED,
            ),
        ],
    ),
    "cloudtrail": ConnectorManifest(
        name="cloudtrail",
        version="0.1.0",
        description="AWS CloudTrail + GuardDuty — events, findings, principal summary.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.AWS_SIGV4,
        queries=[
            _query(
                "aws_cloudtrail_lookup_events",
                "CloudTrail record search.",
                [_O.API_ACTIVITY, _O.AUDIT_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "aws_guardduty_list_findings",
                "GuardDuty findings.",
                [_O.DETECTION_FINDING],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "aws_cloudtrail_principal_summary",
                "Per-principal behavioral rollup.",
                [_O.API_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "gcp": ConnectorManifest(
        name="gcp",
        version="0.1.0",
        description="GCP Cloud Audit Logs + Security Command Center — control-plane telemetry.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.OAUTH2,
        queries=[
            _query(
                "gcp_audit_log_search",
                "Cloud Audit Logs entry search.",
                [_O.API_ACTIVITY, _O.AUDIT_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "gcp_scc_list_findings",
                "Security Command Center findings.",
                [_O.DETECTION_FINDING],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "gcp_audit_principal_summary",
                "Per-principal behavioral rollup.",
                [_O.API_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    "proofpoint": ConnectorManifest(
        name="proofpoint",
        version="0.1.0",
        description="Proofpoint TAP — message events, URL clicks, VAP summary.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BASIC,
        queries=[
            _query(
                "pfpt_message_events_search",
                "TAP message events (delivered + blocked, verdicts).",
                [_O.EMAIL_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
                cost=CostClass.MODERATE,
            ),
            _query(
                "pfpt_click_events_search",
                "TAP URL-click events (permitted + blocked).",
                [_O.EMAIL_ACTIVITY, _O.HTTP_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
            _query(
                "pfpt_vap_summary",
                "Very-Attacked-People per-recipient rollup.",
                [_O.EMAIL_ACTIVITY],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
    ),
    # ------------------------------------------------------------------ #
    # Tier-1 sinks (collaboration writes: BlastRadius.NONE, HITL opt-out)
    # ------------------------------------------------------------------ #
    "jira": ConnectorManifest(
        name="jira",
        version="0.1.0",
        description="Jira Service Management — IR ticket sink.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.API_KEY,
        queries=[
            _query(
                "jira_get_issue",
                "Ticket read-back (fields, comments, history).",
                [],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="jira_create_incident",
                description="Open an IR ticket in the security project.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="jira_add_comment",
                description="Append a ticket comment.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="jira_transition_issue",
                description="Drive the ticket workflow state machine.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
        ],
    ),
    "servicenow": ConnectorManifest(
        name="servicenow",
        version="0.1.0",
        description="ServiceNow SecOps — security-incident (SIR) sink.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BASIC,
        queries=[
            _query(
                "snow_get_security_incident",
                "SIR record read-back (fields, work notes, history).",
                [],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="snow_create_security_incident",
                description="Open a security-incident (SIR) record.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="snow_add_work_note",
                description="Append a SIR work note.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="snow_update_state",
                description="Drive the SIR lifecycle state machine.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
        ],
    ),
    "slack": ConnectorManifest(
        name="slack",
        version="0.1.0",
        description="Slack — incident-commander comms bridge.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BEARER,
        queries=[
            _query(
                "slack_get_channel_history",
                "Channel message read-back, newest-first.",
                [],
                tlp=TLP.AMBER_STRICT,
            ),
        ],
        actions=[
            ActionCapability(
                id="slack_create_incident_channel",
                description="Open the #inc-<slug> bridge channel.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="slack_post_message",
                description="Post to a channel or thread.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
            ActionCapability(
                id="slack_pin_message",
                description="Pin the IC status-of-record message.",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=False,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
        ],
    ),
    "git": ConnectorManifest(
        name="git",
        version="0.1.0",
        description="Detection-rule repository — HITL-gated PR composer.",
        transport=TransportKind.MCP_HTTP,
        auth=CredentialType.BEARER,
        actions=[
            ActionCapability(
                id="git_open_detection_pr",
                description="Open a detection-rule PR (route-level HITL gate).",
                tlp_egress=TLP.AMBER_STRICT,
                hitl_required=True,
                reversible=True,
                blast_radius=BlastRadius.NONE,
            ),
        ],
    ),
}


def get_manifest(server_id: str) -> ConnectorManifest | None:
    """Manifest lookup by MCP ``server_id`` (None for unknown servers)."""
    return MANIFESTS.get(server_id)
