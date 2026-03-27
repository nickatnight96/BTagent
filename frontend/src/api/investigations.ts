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
  severity?: string;
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
  if (params.severity) searchParams.set("severity", params.severity);
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
