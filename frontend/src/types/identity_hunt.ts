/**
 * Identity Hunt UI types (#116 Phase B).
 *
 * TypeScript mirrors of ``shared/btagent_shared/types/identity_hunt.py``.
 * String-union values match the backend StrEnum values exactly so they can be
 * compared without conversion.
 *
 * The ``IdentityFindingEvidence`` interface captures the evidence dict fields
 * that the identity detectors embed in every HuntFinding they emit —
 * ``principal_id``, ``app_id``, ``cred_type``, ``distinct_asns``, etc.  These
 * are typed as optional because the evidence dict is open-ended; the page
 * renders gracefully when fields are absent.
 */

// --------------------------------------------------------------------------- //
// Enums (mirrors Python StrEnum — lowercase string literals)
// --------------------------------------------------------------------------- //

export type IdentityProvider = "okta" | "entra" | "google_workspace" | "generic";

export type IdentityEntityKind =
  | "user"
  | "service_principal"
  | "oauth_app"
  | "session"
  | "device";

export type OAuthConsentType = "admin" | "user" | "pre_authorized" | "unknown";

export type IdentityEventKind =
  | "token_issued"
  | "token_refresh"
  | "token_revoked"
  | "mfa_challenge"
  | "mfa_denied"
  | "mfa_approved"
  | "login_success"
  | "login_failure"
  | "credential_added"
  | "credential_removed"
  | "role_assigned"
  | "role_removed"
  | "federation_trust_modified"
  | "grant_created"
  | "grant_revoked"
  | "app_consent_granted";

// --------------------------------------------------------------------------- //
// Core identity entities (mirrors IdentityEntity Pydantic model)
// --------------------------------------------------------------------------- //

export interface IdentityEntity {
  id: string;
  org_id: string;
  kind: IdentityEntityKind;
  provider: IdentityProvider;
  /** Stable, provider-scoped identifier (UPN, client_id, session token hash, etc.). */
  canonical_id: string;
  display_name: string;
  first_seen: string;
  last_seen: string;
  enrichment: Record<string, unknown>;
}

// --------------------------------------------------------------------------- //
// OAuth grant graph (mirrors OAuthGrant Pydantic model)
// --------------------------------------------------------------------------- //

export interface OAuthGrant {
  id: string;
  org_id: string;
  /** Client / application ID that holds this grant (OAuth client_id). */
  app_id: string;
  app_display_name: string;
  /** User or service account UPN / object_id the grant was consented for. */
  principal_id: string;
  provider: IdentityProvider;
  /** Normalised OAuth scope strings (e.g. 'Mail.Read', 'offline_access'). */
  scopes: string[];
  consent_type: OAuthConsentType;
  granted_at: string;
  last_used: string | null;
  /** null while the grant is active; set when revoked. */
  revoked_at: string | null;
  raw: Record<string, unknown>;
}

// --------------------------------------------------------------------------- //
// Geo location (mirrors GeoLocation Pydantic model)
// --------------------------------------------------------------------------- //

export interface GeoLocation {
  country: string;
  city: string;
  latitude: number | null;
  longitude: number | null;
  /** Autonomous System Number (e.g. 'AS15169') for ASN-diversity checks. */
  asn: string;
}

// --------------------------------------------------------------------------- //
// Identity event (mirrors IdentityEvent Pydantic model)
// --------------------------------------------------------------------------- //

export interface IdentityEvent {
  id: string;
  org_id: string;
  provider: IdentityProvider;
  kind: IdentityEventKind;
  principal_id: string;
  app_id: string;
  session_id: string;
  token_id: string;
  ip_address: string;
  geo: GeoLocation;
  user_agent: string;
  timestamp: string;
  raw: Record<string, unknown>;
}

// --------------------------------------------------------------------------- //
// Evidence dict shape — embedded inside HuntFinding.evidence
// --------------------------------------------------------------------------- //

/**
 * Fields that identity detectors embed in ``HuntFinding.evidence``.
 *
 * All fields are optional because the evidence dict is open-ended; the page
 * must degrade gracefully when any field is absent.  The full set of possible
 * fields is documented in ``IdentityDetectionResult.evidence`` (Python).
 */
export interface IdentityFindingEvidence {
  /** The stable identity principal (UPN, object_id, etc.) implicated. */
  principal_id?: string;
  /** OAuth client / application ID if the detection involves an OAuth grant. */
  app_id?: string;
  /** OAuth app display name, if known. */
  app_display_name?: string;
  /** Credential type implicated (e.g. 'refresh_token', 'access_token', 'sp_secret'). */
  cred_type?: string;
  /** Number of distinct ASNs seen for the same token/session (token-replay signal). */
  distinct_asns?: number;
  /** ASN list for token-replay findings. */
  asns?: string[];
  /** IP addresses seen across ASNs. */
  ip_addresses?: string[];
  /** OAuth scopes on the grant, if applicable. */
  scopes?: string[];
  /** Consent type for OAuth grant findings. */
  consent_type?: OAuthConsentType;
  /** Identity provider for this event. */
  provider?: IdentityProvider;
  /** Number of MFA push challenges in a window (MFA fatigue signal). */
  mfa_push_count?: number;
  /** Number of MFA denials in a window. */
  mfa_deny_count?: number;
  /** Time window in seconds over which MFA events were counted. */
  window_seconds?: number;
  /** Session ID implicated (for token-replay / session-hijack detections). */
  session_id?: string;
  /** Token ID / jti implicated. */
  token_id?: string;
  /** Raw event IDs contributing to this detection. */
  event_ids?: string[];
  /** Time of first event in the detection window. */
  window_start?: string;
  /** Time of last event in the detection window. */
  window_end?: string;
  /** App was dormant for this many days before reactivation. */
  dormant_days?: number;
  /** Whether the app previously had revoked grants (dormant reactivation). */
  previously_revoked?: boolean;
  /** Additional freeform fields from the detector. */
  [key: string]: unknown;
}

// --------------------------------------------------------------------------- //
// Timeline entry (UI-only, derived from finding + evidence)
// --------------------------------------------------------------------------- //

/**
 * A single entry in the per-principal token-lifecycle timeline.
 *
 * Constructed client-side by grouping identity ``HuntFinding``s by
 * ``principal_id`` (from ``evidence``) and sorting by ``created_at``.
 */
export interface IdentityTimelineEntry {
  /** The source HuntFinding id. */
  finding_id: string;
  /** ISO timestamp (``HuntFinding.created_at`` or ``evidence.window_end``). */
  timestamp: string;
  /** Severity from the source finding. */
  severity: string;
  /** Human-readable description derived from the finding title + evidence. */
  label: string;
  /** MITRE ATT&CK technique IDs on the finding. */
  technique_ids: string[];
  /** The raw evidence dict for drilldown. */
  evidence: IdentityFindingEvidence;
  /** The finding's current state. */
  state: string;
  /** The finding's cluster id, if any. */
  cluster_id: string | null;
}

// --------------------------------------------------------------------------- //
// Per-principal summary (UI-only)
// --------------------------------------------------------------------------- //

/**
 * All identity findings grouped by ``principal_id`` from the evidence dict.
 * Used to drive the per-principal timeline and consent panel.
 */
export interface PrincipalSummary {
  /** The principal_id string from the evidence dict. */
  principal_id: string;
  /** Highest severity across all findings for this principal. */
  max_severity: string;
  /** Total number of findings for this principal. */
  finding_count: number;
  /** Chronologically sorted timeline entries. */
  timeline: IdentityTimelineEntry[];
  /** Subset of findings whose technique_ids include consent/credential techniques. */
  consent_findings: IdentityTimelineEntry[];
}

// --------------------------------------------------------------------------- //
// OAuth grant table row (UI-only, derived from evidence)
// --------------------------------------------------------------------------- //

/**
 * A row in the OAuth grant table, extracted from finding evidence fields.
 * Multiple findings for the same principal + app are deduplicated by
 * ``app_id``.
 */
export interface GrantTableRow {
  principal_id: string;
  app_id: string;
  app_display_name: string;
  scopes: string[];
  consent_type: OAuthConsentType | "unknown";
  finding_id: string;
  severity: string;
}
