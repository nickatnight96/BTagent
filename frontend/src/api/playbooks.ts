import api from "./client";
import type {
  Playbook,
  CreatePlaybookRequest,
  UpdatePlaybookRequest,
  PlaybookExecution,
  ValidationResult,
} from "@/types/playbook";

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

interface ListPlaybooksParams {
  page?: number;
  page_size?: number;
  search?: string;
  is_active?: boolean;
  trigger_type?: string;
}

export async function listPlaybooks(
  params: ListPlaybooksParams = {},
): Promise<PaginatedResponse<Playbook>> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set("page", String(params.page));
  if (params.page_size) searchParams.set("page_size", String(params.page_size));
  if (params.search) searchParams.set("search", params.search);
  if (params.is_active !== undefined) searchParams.set("is_active", String(params.is_active));
  if (params.trigger_type) searchParams.set("trigger_type", params.trigger_type);

  const query = searchParams.toString();
  const endpoint = `/v1/playbooks${query ? `?${query}` : ""}`;
  return api.get<PaginatedResponse<Playbook>>(endpoint);
}

export async function getPlaybook(id: string): Promise<Playbook> {
  return api.get<Playbook>(`/v1/playbooks/${id}`);
}

export async function createPlaybook(data: CreatePlaybookRequest): Promise<Playbook> {
  return api.post<Playbook>("/v1/playbooks", data);
}

export async function updatePlaybook(
  id: string,
  data: UpdatePlaybookRequest,
): Promise<Playbook> {
  return api.put<Playbook>(`/v1/playbooks/${id}`, data);
}

export async function deletePlaybook(id: string): Promise<void> {
  return api.delete<void>(`/v1/playbooks/${id}`);
}

export async function validatePlaybook(
  data: CreatePlaybookRequest,
): Promise<ValidationResult> {
  return api.post<ValidationResult>("/v1/playbooks/validate", data);
}

// Backend returns ``step_results`` as ``dict[str, StepResult]`` keyed by
// step id; the frontend stores + iterates an array. Normalise here so
// every consumer sees the same shape.
function _normalizeExecution<T extends { step_results?: unknown }>(exec: T): T {
  const sr = exec.step_results;
  if (sr && typeof sr === "object" && !Array.isArray(sr)) {
    exec.step_results = Object.values(sr) as T["step_results"];
  }
  return exec;
}

export async function executePlaybook(
  id: string,
  investigationId?: string,
): Promise<PlaybookExecution> {
  const exec = await api.post<PlaybookExecution>(`/v1/playbooks/${id}/execute`, {
    investigation_id: investigationId,
  });
  return _normalizeExecution(exec);
}

export async function getExecutions(
  playbookId: string,
): Promise<PaginatedResponse<PlaybookExecution>> {
  return api.get<PaginatedResponse<PlaybookExecution>>(
    `/v1/playbooks/${playbookId}/executions`,
  );
}

export async function getExecution(executionId: string): Promise<PlaybookExecution> {
  // Backend's executions live at /v1/playbooks/executions/{id}; the
  // bare /v1/executions path 404s. The frontend store polls this
  // every 2s while a run is in progress.
  const exec = await api.get<PlaybookExecution>(
    `/v1/playbooks/executions/${executionId}`,
  );
  return _normalizeExecution(exec);
}
