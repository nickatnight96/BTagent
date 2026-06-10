import api from "./client";

// --------------------------------------------------------------------------- //
// Types — mirror shared/btagent_shared/types/workflow.py + the engine
// Workflow graph shape (compiler/workflow.py) stored in version.definition.
// --------------------------------------------------------------------------- //

export type WorkflowVersionState = "draft" | "published" | "deprecated";

export type WorkflowRunStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "failed"
  | "paused";

export type TLP = "red" | "amber_strict" | "amber" | "green" | "white";

/** A node in the compiled engine Workflow graph (version.definition.nodes[]). */
export interface WorkflowGraphNode {
  step_id: string;
  node_id: string;
  name: string;
  config: Record<string, unknown>;
}

/** An edge in the compiled engine Workflow graph (version.definition.edges[]). */
export interface WorkflowGraphEdge {
  source: string;
  target: string;
  label: string;
}

/** The engine Workflow serialized into version.definition (may be {} for an empty draft). */
export interface WorkflowDefinition {
  name?: string;
  version?: string;
  description?: string;
  trigger?: Record<string, unknown>;
  nodes?: WorkflowGraphNode[];
  edges?: WorkflowGraphEdge[];
}

export interface Workflow {
  id: string;
  name: string;
  description: string;
  org_id: string;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface WorkflowVersion {
  id: string;
  workflow_id: string;
  version_number: number;
  state: WorkflowVersionState;
  definition: WorkflowDefinition;
  org_id: string;
  created_by: string | null;
  created_at: string;
  published_at: string | null;
  deprecated_at: string | null;
}

/** One hash-linked audit entry (engine EvidenceRecord JSON). */
export interface EvidenceRecord {
  run_id: string;
  node_id: string;
  prev_hash: string;
  link_hash: string;
  input_hash: string;
  output_hash: string;
  timestamp: string;
}

export interface WorkflowRun {
  id: string;
  workflow_id: string;
  version_id: string;
  version_number: number;
  org_id: string;
  triggered_by: string | null;
  investigation_id: string | null;
  status: WorkflowRunStatus;
  /** When paused, the step id awaiting approval. */
  paused_node_id: string | null;
  /** Step ids approved across resume cycles. */
  approved_steps: string[];
  trigger_payload: Record<string, unknown>;
  outputs: Record<string, unknown>;
  final_output: Record<string, unknown> | null;
  nodes_executed: string[];
  evidence_chain: EvidenceRecord[];
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface WorkflowListResponse {
  items: Workflow[];
  total: number;
}

export interface WorkflowVersionListResponse {
  items: WorkflowVersion[];
  total: number;
}

export interface WorkflowRunListResponse {
  items: WorkflowRun[];
  total: number;
}

export interface CreateWorkflowRequest {
  name: string;
  description?: string;
  definition?: WorkflowDefinition;
}

export interface UpdateWorkflowRequest {
  name?: string;
  description?: string;
}

export interface CreateWorkflowVersionRequest {
  definition: WorkflowDefinition;
}

export interface UpdateWorkflowVersionRequest {
  definition: WorkflowDefinition;
}

export interface RunWorkflowRequest {
  trigger_payload?: Record<string, unknown>;
  /** Omit to fail-closed at TLP.RED; or inherit from investigation_id. */
  active_tlp?: TLP;
  investigation_id?: string;
}

// --------------------------------------------------------------------------- //
// Workflow CRUD
// --------------------------------------------------------------------------- //

export async function listWorkflows(
  params: { page?: number; page_size?: number } = {},
): Promise<WorkflowListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<WorkflowListResponse>(`/v1/workflows${q ? `?${q}` : ""}`);
}

export async function getWorkflow(id: string): Promise<Workflow> {
  return api.get<Workflow>(`/v1/workflows/${id}`);
}

export async function createWorkflow(data: CreateWorkflowRequest): Promise<Workflow> {
  return api.post<Workflow>("/v1/workflows", data);
}

export async function updateWorkflow(
  id: string,
  data: UpdateWorkflowRequest,
): Promise<Workflow> {
  return api.patch<Workflow>(`/v1/workflows/${id}`, data);
}

// --------------------------------------------------------------------------- //
// Versions
// --------------------------------------------------------------------------- //

export async function listVersions(workflowId: string): Promise<WorkflowVersionListResponse> {
  return api.get<WorkflowVersionListResponse>(`/v1/workflows/${workflowId}/versions`);
}

export async function getVersion(
  workflowId: string,
  versionNumber: number,
): Promise<WorkflowVersion> {
  return api.get<WorkflowVersion>(`/v1/workflows/${workflowId}/versions/${versionNumber}`);
}

export async function createVersion(
  workflowId: string,
  data: CreateWorkflowVersionRequest,
): Promise<WorkflowVersion> {
  return api.post<WorkflowVersion>(`/v1/workflows/${workflowId}/versions`, data);
}

export async function updateVersion(
  workflowId: string,
  versionNumber: number,
  data: UpdateWorkflowVersionRequest,
): Promise<WorkflowVersion> {
  return api.patch<WorkflowVersion>(
    `/v1/workflows/${workflowId}/versions/${versionNumber}`,
    data,
  );
}

export async function publishVersion(
  workflowId: string,
  versionNumber: number,
): Promise<WorkflowVersion> {
  return api.post<WorkflowVersion>(
    `/v1/workflows/${workflowId}/versions/${versionNumber}/publish`,
  );
}

export async function deprecateVersion(
  workflowId: string,
  versionNumber: number,
): Promise<WorkflowVersion> {
  return api.post<WorkflowVersion>(
    `/v1/workflows/${workflowId}/versions/${versionNumber}/deprecate`,
  );
}

// --------------------------------------------------------------------------- //
// Node catalog (canvas palette)
// --------------------------------------------------------------------------- //

export type NodeCategory =
  | "trigger"
  | "integration"
  | "reasoning"
  | "knowledge"
  | "decision"
  | "data"
  | "output";

export interface NodeCatalogEntry {
  id: string;
  name: string;
  version: string;
  category: NodeCategory | string;
  description: string;
  /** JSON Schema of the node's pydantic input model; {} when none. */
  input_schema: Record<string, unknown>;
}

export interface NodeCatalogResponse {
  items: NodeCatalogEntry[];
  total: number;
}

export async function getNodeCatalog(): Promise<NodeCatalogResponse> {
  return api.get<NodeCatalogResponse>("/v1/workflows/node-catalog");
}

// --------------------------------------------------------------------------- //
// Execution + run history
// --------------------------------------------------------------------------- //

export async function runVersion(
  workflowId: string,
  versionNumber: number,
  data: RunWorkflowRequest = {},
): Promise<WorkflowRun> {
  return api.post<WorkflowRun>(
    `/v1/workflows/${workflowId}/versions/${versionNumber}/run`,
    data,
  );
}

export async function listRuns(
  workflowId: string,
  params: { page?: number; page_size?: number } = {},
): Promise<WorkflowRunListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<WorkflowRunListResponse>(
    `/v1/workflows/${workflowId}/runs${q ? `?${q}` : ""}`,
  );
}

export async function getRun(workflowId: string, runId: string): Promise<WorkflowRun> {
  return api.get<WorkflowRun>(`/v1/workflows/${workflowId}/runs/${runId}`);
}

/** Approve a paused run's gate and resume it (requires hitl:approve). */
export async function resumeRun(workflowId: string, runId: string): Promise<WorkflowRun> {
  return api.post<WorkflowRun>(`/v1/workflows/${workflowId}/runs/${runId}/resume`);
}
