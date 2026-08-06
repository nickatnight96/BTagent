import api from "./client";
import type {
  Investigation,
  CreateInvestigationRequest,
  ChatMessage,
} from "@/types/investigation";

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

interface ListInvestigationsParams {
  page?: number;
  page_size?: number;
  status?: string;
  // `severity` was here with no caller; the route does not declare it, so it
  // would have been discarded silently. Removed rather than left as a field
  // that looks like a filter and is not one.
  //
  // `search` IS sent (the list page passes it) and IS ignored by the route —
  // InvestigationList compensates by filtering client-side, which means search
  // only ever matches within the page already loaded. Tracked as debt in
  // backend/tests/test_api_query_param_parity.py rather than silently dropped
  // here, because removing it would quietly narrow the feature further.
  search?: string;
}

export async function createInvestigation(
  data: CreateInvestigationRequest,
): Promise<Investigation> {
  return api.post<Investigation>("/v1/investigations", data);
}

export async function listInvestigations(
  params: ListInvestigationsParams = {},
): Promise<PaginatedResponse<Investigation>> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set("page", String(params.page));
  if (params.page_size) searchParams.set("page_size", String(params.page_size));
  if (params.status) searchParams.set("status", params.status);
  if (params.search) searchParams.set("search", params.search);

  const query = searchParams.toString();
  const endpoint = `/v1/investigations${query ? `?${query}` : ""}`;
  return api.get<PaginatedResponse<Investigation>>(endpoint);
}

export async function getInvestigation(id: string): Promise<Investigation> {
  return api.get<Investigation>(`/v1/investigations/${id}`);
}

export async function pauseInvestigation(id: string): Promise<Investigation> {
  return api.post<Investigation>(`/v1/investigations/${id}/pause`);
}

export async function resumeInvestigation(id: string): Promise<Investigation> {
  return api.post<Investigation>(`/v1/investigations/${id}/resume`);
}

export async function stopInvestigation(id: string): Promise<Investigation> {
  return api.post<Investigation>(`/v1/investigations/${id}/stop`);
}

export async function chatInvestigation(
  id: string,
  message: string,
): Promise<ChatMessage> {
  return api.post<ChatMessage>(`/v1/investigations/${id}/chat`, { message });
}

export async function getInvestigationHistory(
  id: string,
): Promise<ChatMessage[]> {
  return api.get<ChatMessage[]>(`/v1/investigations/${id}/history`);
}
