import api from "./client";

export interface MitreTag {
  technique_id: string;
  name: string;
  confidence: number;
}

export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  source_connector: string;
  ocsf_event_class: string;
  source_ip: string | null;
  dest_ip: string | null;
  user: string | null;
  host: string | null;
  file_hash: string | null;
  domain: string | null;
  action: string | null;
  summary: string;
  mitre_techniques: MitreTag[];
}

export interface PivotSuggestion {
  entity_type: string;
  entity_value: string;
  rationale: string;
  suggested_connectors: string[];
}

export interface AuditEntry {
  connector: string;
  capability_id: string;
  query: string;
  queried_at: string;
  event_count: number;
  error: string | null;
}

export interface CorrelationTimeline {
  entity_type: string;
  entity_value: string;
  events: NormalizedEvent[];
  sources_queried: string[];
  pivots: PivotSuggestion[];
  audit_trail: AuditEntry[];
  mock_mode: boolean;
}

export interface CorrelateRequest {
  entity_type: string;
  entity_value: string;
  mitre_confidence_threshold?: number;
}

export async function correlateEntity(
  req: CorrelateRequest
): Promise<CorrelationTimeline> {
  return api.post<CorrelationTimeline>("/api/v1/hunts/correlate", req);
}
