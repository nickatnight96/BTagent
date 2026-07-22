import api from "./client";

// Mirrors btagent_shared.types.hunt_package.HuntPackage (UC-2.2).
export interface Sighting {
  ioc_value: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  source_connectors: string[];
  event_ids: string[];
}

export interface RetroHuntReport {
  window_days: number;
  iocs_checked: number;
  sightings: Sighting[];
  sightings_by_tactic: Record<string, Sighting[]>;
  techniques_with_sightings: string[];
  coverage_gaps: string[];
  compromise_suspected: boolean;
  generated_at: string;
  mock_mode: boolean;
}

export interface HuntQuery {
  backend: string;
  query: string;
  notes: string;
}

export interface SigmaDraft {
  technique_id: string;
  title: string;
  sigma_yaml: string;
  rationale: string;
}

export interface HuntPackage {
  /** Persisted-store id (hpkg_*); null on dumps predating persistence. */
  id?: string | null;
  source_label: string;
  extracted_ioc_count: number;
  deduped_count: number;
  derived_techniques: string[];
  retro_report: RetroHuntReport | null;
  queries: Record<string, Record<string, HuntQuery>>;
  sigma_drafts: SigmaDraft[];
  generated_at: string;
  mock_mode: boolean;
}

export interface HuntPackageRequest {
  text: string;
  source_label?: string;
  backends?: string[];
  window_days?: number;
}

export async function generateHuntPackage(
  req: HuntPackageRequest
): Promise<HuntPackage> {
  return api.post<HuntPackage>("/v1/hunts/package", req);
}

// --- Package history (#99) — mirrors HuntPackageSummary in api/v1/hunts.py --- //

export interface HuntPackageSummary {
  id: string;
  source_label: string;
  extracted_ioc_count: number;
  deduped_count: number;
  techniques: string[];
  mock_mode: boolean;
  created_by: string | null;
  created_at: string;
}

export interface HuntPackageListResponse {
  items: HuntPackageSummary[];
  total: number;
}

export async function listHuntPackages(
  params: { page?: number; page_size?: number } = {}
): Promise<HuntPackageListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<HuntPackageListResponse>(`/v1/hunts/packages${q ? `?${q}` : ""}`);
}

export async function getHuntPackage(id: string): Promise<HuntPackage> {
  return api.get<HuntPackage>(`/v1/hunts/packages/${id}`);
}
