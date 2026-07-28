import api, { ApiError } from "./client";
import type { IOCType } from "@/types/ioc";

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
  req: HuntPackageRequest,
): Promise<HuntPackage> {
  return api.post<HuntPackage>("/v1/hunts/package", req);
}

/**
 * Generate a hunt package from an uploaded advisory file (PDF or CSV).
 *
 * A raw fetch rather than `api.post`, which unconditionally JSON-stringifies
 * its body — multipart needs the browser to set the boundary itself (same
 * precedent as `exportHuntPlan`). Non-OK responses are rethrown as
 * `ApiError` so the server's contentful refusals — 422 "file is empty" /
 * "no text extracted", 400 "undecodable PDF" — reach the analyst verbatim
 * instead of flattening to "upload failed".
 */
export async function uploadHuntPackage(
  file: File,
  opts: { source_label?: string; backends?: string[] } = {},
): Promise<HuntPackage> {
  const form = new FormData();
  form.append("file", file);
  if (opts.source_label) form.append("source_label", opts.source_label);
  for (const b of opts.backends ?? []) form.append("backends", b);

  const response = await fetch(
    `${import.meta.env.VITE_API_BASE_URL ?? "/api"}/v1/hunts/package/upload`,
    { method: "POST", body: form, credentials: "include" },
  );
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, response.statusText, body);
  }
  return body as HuntPackage;
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
  params: { page?: number; page_size?: number } = {},
): Promise<HuntPackageListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<HuntPackageListResponse>(
    `/v1/hunts/packages${q ? `?${q}` : ""}`,
  );
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
export async function promoteHuntPackage(
  id: string,
): Promise<PromotePackageResponse> {
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

/** One indicator submitted as hunt input (#99) — mirrors HuntPlanIOC. */
export interface HuntPlanIOC {
  type: IOCType;
  value: string;
}

export interface HuntPlanRequest {
  adversaries?: string[];
  ttps?: string[];
  /**
   * Indicators to hunt from. The backend maps each to a plausible technique,
   * so an analyst holding only indicators can still get a plan.
   */
  iocs?: HuntPlanIOC[];
  backends?: string[];
}

/**
 * Best-effort IOC type from a raw indicator string.
 *
 * The analyst pastes bare values; asking them to tag each one by hand would
 * make the field unusable for the case it exists for (a handful of
 * indicators from an advisory). Ordered most- to least-specific: hashes are
 * fixed-length hex, so they must be tested before the looser domain rule,
 * and a bare "8.8.8.8" must not be read as a domain.
 *
 * Anything unrecognised returns "other", which the backend's technique map
 * has no entry for — such an IOC is carried but contributes no hypothesis,
 * rather than silently inventing the wrong one.
 */
export function inferIOCType(raw: string): IOCType {
  const v = raw.trim();
  if (/^[a-fA-F0-9]{32}$/.test(v)) return "hash_md5";
  if (/^[a-fA-F0-9]{40}$/.test(v)) return "hash_sha1";
  if (/^[a-fA-F0-9]{64}$/.test(v)) return "hash_sha256";
  if (/^CVE-\d{4}-\d{4,}$/i.test(v)) return "cve";
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return "email";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
  if (/^[/\\]|^[a-zA-Z]:[/\\]/.test(v)) return "file_path";
  if (/^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/.test(v))
    return "domain";
  return "other";
}

/** Generate a full hunt runbook from adversaries, ATT&CK technique ids, and/or IOCs. */
export async function generateHuntPlan(
  req: HuntPlanRequest,
): Promise<HuntPlan> {
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
  /** Findings from the most recent execution; null until first run. */
  last_run_findings: number | null;
  /** Timestamp of the most recent execution; null until first run. */
  last_run_at: string | null;
}

export interface HuntPlanListResponse {
  items: HuntPlanSummary[];
  total: number;
}

export async function listHuntPlans(
  params: { page?: number; page_size?: number } = {},
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

export interface ExecuteHuntPlanResponse {
  plan_id: string;
  status: string;
  /** True on the live-connector path — the run happens on the worker. */
  queued: boolean;
  /** Findings landed in the triage inbox; null when queued. */
  findings_created: number | null;
}

/** Run a stored plan's runbook; hits land in the hunt triage inbox. */
export async function executeHuntPlan(
  id: string,
): Promise<ExecuteHuntPlanResponse> {
  return api.post<ExecuteHuntPlanResponse>(`/v1/hunts/plans/${id}/execute`);
}

/** Download a stored plan's runbook as a Markdown or PDF blob (#343). */
export async function exportHuntPlan(
  id: string,
  format: "md" | "pdf",
): Promise<Blob> {
  const response = await fetch(
    `${import.meta.env.VITE_API_BASE_URL ?? "/api"}/v1/hunts/plans/${id}/export?format=${format}`,
    {
      method: "GET",
      // httpOnly-cookie auth, same as the main api client.
      credentials: "include",
    },
  );
  if (!response.ok) {
    throw new Error(`Export failed (${response.status})`);
  }
  return response.blob();
}

// --- Per-run execution history (#341) -------------------------------------- //

export interface HuntPlanRun {
  id: string;
  plan_row_id: string;
  proposal_id: string | null;
  plan_id: string;
  run_id: string;
  ttp_stats: Record<string, { hits: number; errors: string[] }>;
  hit_count: number;
  error_count: number;
  findings_created: number;
  status: string;
  error: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface HuntPlanRunListResponse {
  items: HuntPlanRun[];
  total: number;
}

export async function listHuntPlanRuns(
  id: string,
  params: { page?: number; page_size?: number } = {},
): Promise<HuntPlanRunListResponse> {
  const sp = new URLSearchParams();
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<HuntPlanRunListResponse>(
    `/v1/hunts/plans/${id}/runs${q ? `?${q}` : ""}`,
  );
}

// --------------------------------------------------------------------------
// Hunt-pack suggestions (#120/#112)
//
// A pattern-hunt proposal that keeps hitting is written out as a *suggested*
// recurring pack. The write side landed first; these are the read + decide
// halves, so a suggestion can be reviewed and armed from the product rather
// than only from the database.
// --------------------------------------------------------------------------

export type PackSuggestionState = "suggested" | "accepted" | "dismissed";

export interface HuntPackSuggestion {
  id: string;
  proposal_id: string;
  plan_id: string;
  title: string;
  technique_ids: string[];
  rationale: string;
  state: PackSuggestionState;
  hit_count: number;
  created_at: string;
  updated_at: string;
  /** The promotable HuntPackManifest draft — the actual Sigma, for review. */
  manifest: Record<string, unknown>;
}

export interface HuntPackSuggestionListResponse {
  items: HuntPackSuggestion[];
  total: number;
}

/** Suggested recurring packs, newest/most-hit first. Requires `hunt:view`. */
export async function listPackSuggestions(
  params: { state?: PackSuggestionState; page?: number; page_size?: number } = {},
): Promise<HuntPackSuggestionListResponse> {
  const sp = new URLSearchParams();
  if (params.state) sp.set("state", params.state);
  if (params.page) sp.set("page", String(params.page));
  if (params.page_size) sp.set("page_size", String(params.page_size));
  const q = sp.toString();
  return api.get<HuntPackSuggestionListResponse>(
    `/v1/hunts/pack-suggestions${q ? `?${q}` : ""}`,
  );
}

/**
 * Accept or dismiss a suggestion. Requires `hunt:promote` (senior_analyst+) —
 * accepting arms a recurring pack, which is a durable commitment rather than
 * a triage call, so it sits above plain `hunt:view`.
 */
export async function decidePackSuggestion(
  id: string,
  state: "accepted" | "dismissed",
): Promise<HuntPackSuggestion> {
  return api.post<HuntPackSuggestion>(
    `/v1/hunts/pack-suggestions/${encodeURIComponent(id)}/decide`,
    { state },
  );
}
