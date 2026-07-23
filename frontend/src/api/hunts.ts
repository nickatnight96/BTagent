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
  /** Investigation this package was promoted into; null until promoted. */
  investigation_id?: string | null;
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
  /** Case this package was promoted into; null until promoted. */
  investigation_id: string | null;
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

export interface PromotePackageResponse {
  investigation_id: string;
  package_id: string;
  title: string;
  severity: string;
  status: string;
}

/** Open an investigation from a stored package (one-shot; 409 if already promoted). */
export async function promoteHuntPackage(id: string): Promise<PromotePackageResponse> {
  return api.post<PromotePackageResponse>(`/v1/hunts/packages/${id}/promote`);
}

// --------------------------------------------------------------------------- //
// Direct hunt planning (#99 Phase A) — mirrors btagent_shared.types.hunt
// --------------------------------------------------------------------------- //

export interface HuntPlanQuery {
  backend: string;
  query: string;
  notes: string;
}

export interface NoiseProfile {
  expected_hits_per_day: number | null;
  sample_window_days: number | null;
  computed_at: string | null;
}

export interface Hypothesis {
  id: string;
  ttp_id: string;
  ttp_name: string;
  rationale: string;
  behavioral_description: string;
  priority: number;
  sources: string[];
}

export interface TTPRunbookEntry {
  ttp_id: string;
  ttp_name: string;
  rationale: string;
  behavioral_description: string;
  queries: Record<string, HuntPlanQuery>;
  expected_noise: NoiseProfile;
  pivot_questions: string[];
  evidence_checklist: string[];
  owner_id: string | null;
  state: string;
}

export interface ExecSummary {
  adversary_profile: string;
  scope_description: string;
  success_criteria: string;
  estimated_effort_hours: number | null;
  coverage_delta: Record<string, boolean>;
}

export interface HuntPlan {
  id: string;
  org_id: string;
  state: string;
  input: {
    adversaries: string[];
    ttps: string[];
  };
  executive_summary: ExecSummary;
  hypotheses: Hypothesis[];
  ttp_entries: TTPRunbookEntry[];
  created_at: string;
}

export interface HuntPlanRequest {
  adversaries?: string[];
  ttps?: string[];
  backends?: string[];
}

/** Generate a full hunt runbook from adversaries and/or ATT&CK technique ids. */
export async function generateHuntPlan(req: HuntPlanRequest): Promise<HuntPlan> {
  return api.post<HuntPlan>("/v1/hunts/plan", req);
}

// --- Plan history (#337) — mirrors HuntPlanSummary in api/v1/hunts.py ------ //

export interface HuntPlanSummary {
  id: string;
  status: string;
  adversaries: string[];
  ttps: string[];
  hypothesis_count: number;
  entry_count: number;
  /** True when the plan was compiled from a pattern-hunt proposal. */
  from_proposal: boolean;
  created_at: string;
}

export interface HuntPlanListResponse {
  items: HuntPlanSummary[];
  total: number;
}

export async function listHuntPlans(
  params: { page?: number; page_size?: number } = {}
): Promise<HuntPlanListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<HuntPlanListResponse>(`/v1/hunts/plans${q ? `?${q}` : ""}`);
}

export async function getHuntPlan(id: string): Promise<HuntPlan> {
  return api.get<HuntPlan>(`/v1/hunts/plans/${id}`);
}
