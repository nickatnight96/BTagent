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
