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
  // Backend mounts the navigator export at /v1/mitre/export/navigator
  // (see backend/btagent_backend/api/v1/mitre.py:243); the previous
  // ``/navigator/export`` path returned 404 silently because the
  // store's catch swallowed the error.
  const endpoint = `/v1/mitre/export/navigator${buildQuery(params)}`;
  return api.get<NavigatorLayer>(endpoint);
}

export async function searchTTPs(
  query: string,
): Promise<PaginatedResponse<MitreTechnique>> {
  // Backend expects ``q`` (see backend/btagent_backend/api/v1/mitre.py).
  // The previous ``search`` key was silently ignored, which is why the
  // search-narrow + empty-state tests in matrix.spec.ts never resolved.
  const endpoint = `/v1/mitre/techniques${buildQuery({ q: query, page_size: 1000 })}`;
  return api.get<PaginatedResponse<MitreTechnique>>(endpoint);
}

// --- Technique exercise tracking (#99 Phase C, PR #347) --------------------- //

export interface TechniqueExercise {
  technique_id: string;
  last_exercised_at: string;
  last_plan_id: string;
  last_run_id: string;
  last_outcome: string;
  exercise_count: number;
}

export interface TechniqueExerciseListResponse {
  items: TechniqueExercise[];
  total: number;
}

/** Org-scoped hunt exercise records; older_than_days surfaces stale coverage. */
export async function listTechniqueExercises(params?: {
  older_than_days?: number;
  outcome?: string;
}): Promise<TechniqueExerciseListResponse> {
  return api.get<TechniqueExerciseListResponse>(
    `/v1/mitre/exercises${buildQuery(params ?? {})}`,
  );
}
