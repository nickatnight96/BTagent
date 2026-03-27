import api from "./client";
import type {
  MitreTechnique,
  MitreTactic,
  MitreGroup,
  CoverageData,
  DetectionGap,
  NavigatorLayer,
} from "@/types/mitre";

interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      searchParams.set(key, String(value));
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : "";
}

export async function listTechniques(params?: {
  tactic_id?: string;
  search?: string;
  page?: number;
  page_size?: number;
}): Promise<PaginatedResponse<MitreTechnique>> {
  const endpoint = `/v1/mitre/techniques${buildQuery(params ?? {})}`;
  return api.get<PaginatedResponse<MitreTechnique>>(endpoint);
}

export async function getTechnique(id: string): Promise<MitreTechnique> {
  return api.get<MitreTechnique>(`/v1/mitre/techniques/${id}`);
}

export async function listTactics(): Promise<MitreTactic[]> {
  return api.get<MitreTactic[]>("/v1/mitre/tactics");
}

export async function getCoverage(
  investigationId?: string,
): Promise<CoverageData> {
  const params = investigationId ? { investigation_id: investigationId } : {};
  const endpoint = `/v1/mitre/coverage${buildQuery(params)}`;
  return api.get<CoverageData>(endpoint);
}

export async function getCoverageScore(
  investigationId?: string,
): Promise<{ score: number; tagged: number; total: number }> {
  const params = investigationId ? { investigation_id: investigationId } : {};
  const endpoint = `/v1/mitre/coverage/score${buildQuery(params)}`;
  return api.get<{ score: number; tagged: number; total: number }>(endpoint);
}

export async function getDetectionGaps(
  investigationId?: string,
): Promise<DetectionGap[]> {
  const params = investigationId ? { investigation_id: investigationId } : {};
  const endpoint = `/v1/mitre/detection-gaps${buildQuery(params)}`;
  return api.get<DetectionGap[]>(endpoint);
}

export async function listGroups(params?: {
  search?: string;
  page?: number;
  page_size?: number;
}): Promise<PaginatedResponse<MitreGroup>> {
  const endpoint = `/v1/mitre/groups${buildQuery(params ?? {})}`;
  return api.get<PaginatedResponse<MitreGroup>>(endpoint);
}

export async function exportNavigator(
  investigationId?: string,
): Promise<NavigatorLayer> {
  const params = investigationId ? { investigation_id: investigationId } : {};
  const endpoint = `/v1/mitre/navigator/export${buildQuery(params)}`;
  return api.get<NavigatorLayer>(endpoint);
}

export async function searchTTPs(
  query: string,
): Promise<PaginatedResponse<MitreTechnique>> {
  const endpoint = `/v1/mitre/techniques${buildQuery({ search: query })}`;
  return api.get<PaginatedResponse<MitreTechnique>>(endpoint);
}
