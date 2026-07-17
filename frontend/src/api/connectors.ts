import api from "./client";

// Mirrors backend btagent_shared.types.connector — only the read-model
// fields the Integrations view needs. The list endpoint returns compact
// summaries; the detail endpoint returns the full ConnectorManifest.

export interface ConnectorSummary {
  name: string;
  version: string;
  description: string;
  transport: string;
  auth: string;
  query_count: number;
  action_count: number;
  stream_count: number;
  has_hitl_actions: boolean;
  ocsf_emits: string[];
}

export interface ConnectorListResponse {
  items: ConnectorSummary[];
  total: number;
}

export interface Capability {
  id: string;
  kind: "query" | "action" | "stream";
  description: string;
  ocsf_emits: string[];
  tlp_egress: string;
  cost_class: string;
  hitl_required: boolean;
  // action-only
  reversible?: boolean;
  blast_radius?: string;
}

export interface ConnectorManifest {
  name: string;
  version: string;
  description: string;
  transport: string;
  auth: string;
  queries: Capability[];
  actions: Capability[];
  streams: Capability[];
}

export async function listConnectors(params?: {
  emits?: string;
  hasActions?: boolean;
}): Promise<ConnectorListResponse> {
  const qs = new URLSearchParams();
  if (params?.emits) qs.set("emits", params.emits);
  if (params?.hasActions !== undefined) {
    qs.set("has_actions", String(params.hasActions));
  }
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return api.get<ConnectorListResponse>(`/v1/connectors${suffix}`);
}

export async function getConnector(name: string): Promise<ConnectorManifest> {
  return api.get<ConnectorManifest>(`/v1/connectors/${name}`);
}
