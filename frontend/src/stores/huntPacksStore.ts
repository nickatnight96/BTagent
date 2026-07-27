/**
 * HuntPacks (Phase B) Zustand store (#112).
 *
 * The installed-packs view is derived — read-only — from two existing hunt
 * endpoints:
 *
 *   - ``GET /hunt/pack-runs``     → the pack-run history (per-rule ``rule_stats``
 *                                   + hit volumes + last-run status).
 *   - ``GET /hunt/noise-baseline``→ the chronically-hitting (over-firing) rules.
 *
 * There is no dedicated "installed packs" endpoint yet (the per-org pack store
 * is deferred), so the list of installed packs is inferred by grouping the run
 * history by ``pack_id``. Per-rule health is classified into the five
 * :type:`HuntRuleState` values from the run history + the noise baseline.
 *
 * Enable/disable is a **client-side** toggle only — persisting a per-org
 * enable/disable decision is a deferred follow-up, so the switch here changes
 * local view state (which packs are muted from the operator's own screen) and
 * is intentionally not sent to the backend.
 *
 * The pure derivation helpers are exported so they can be unit-tested without a
 * running store (mirrors ``cloudStore`` / ``behavioralStore``).
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import { getNoiseBaseline, listPackRuns } from "@/api/hunt";
import type {
  HuntPackRun,
  HuntPackRunRuleStat,
  HuntRuleState,
  NoiseBaseline,
  NoisyRule,
} from "@/types/hunt";

// How many of the most recent runs to pull for the view.
const RUN_PAGE_SIZE = 200;
// Days of history the hit-volume sparkline spans.
export const HIT_VOLUME_DAYS = 30;
// A rule observed in at least this many runs with zero hits throughout is
// flagged UNDER_FIRING (a possible coverage gap / stale rule), matching the
// backend noise-baseline's ``min_runs`` floor.
export const UNDER_FIRING_MIN_RUNS = 3;

// ---------------------------------------------------------------------------
// Derived-view types
// ---------------------------------------------------------------------------

/** One rule's health + provenance inside an installed pack. */
export interface RuleStatus {
  rule_id: string;
  title: string;
  state: HuntRuleState;
  last_hits: number;
  last_errors: number;
  runs_observed: number;
  total_hits: number;
  /** Fraction of observed runs the rule hit in (0–1). */
  hit_rate: number;
  /** Transpiled query per backend, from the rule's most recent run. */
  queries: Record<string, string>;
}

/** One point in a pack's daily hit-volume sparkline. */
export interface HitVolumePoint {
  day: string; // YYYY-MM-DD (UTC)
  hits: number;
}

/** One installed pack, rolled up from its run history. */
export interface InstalledPack {
  pack_id: string;
  pack_name: string;
  pack_version: string;
  backends: string[];
  /** Newest run for the pack, or null if somehow none. */
  last_run: HuntPackRun | null;
  run_count: number;
  hit_volume_30d: HitVolumePoint[];
  rules: RuleStatus[];
}

// ---------------------------------------------------------------------------
// Pure derivation helpers (exported for unit tests)
// ---------------------------------------------------------------------------

function runTime(run: HuntPackRun): number {
  return new Date(run.started_at).getTime();
}

/** Group runs by ``pack_id``, each group newest-first. */
export function groupRunsByPack(runs: HuntPackRun[]): Map<string, HuntPackRun[]> {
  const groups = new Map<string, HuntPackRun[]>();
  for (const run of runs) {
    const bucket = groups.get(run.pack_id) ?? [];
    bucket.push(run);
    groups.set(run.pack_id, bucket);
  }
  for (const bucket of groups.values()) {
    bucket.sort((a, b) => runTime(b) - runTime(a));
  }
  return groups;
}

/** Index the noise baseline by ``pack_id:rule_id`` for O(1) over-firing lookup. */
export function indexBaseline(baseline: NoiseBaseline | null): Map<string, NoisyRule> {
  const map = new Map<string, NoisyRule>();
  for (const r of baseline?.items ?? []) {
    map.set(`${r.pack_id}:${r.rule_id}`, r);
  }
  return map;
}

/**
 * A daily hit-volume series over the last ``HIT_VOLUME_DAYS`` days (oldest
 * first), summing every run's ``hit_count`` into its UTC day bucket. Days with
 * no run contribute a zero so the sparkline has a stable, evenly-spaced x-axis.
 */
export function build30dHitVolume(
  runs: HuntPackRun[],
  now: Date = new Date(),
): HitVolumePoint[] {
  const byDay = new Map<string, number>();
  for (const run of runs) {
    const day = run.started_at.slice(0, 10); // YYYY-MM-DD
    byDay.set(day, (byDay.get(day) ?? 0) + (run.hit_count || 0));
  }
  const points: HitVolumePoint[] = [];
  // Anchor on UTC midnight so buckets line up with the ``slice(0,10)`` keys.
  const anchor = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  for (let i = HIT_VOLUME_DAYS - 1; i >= 0; i--) {
    const d = new Date(anchor - i * 86_400_000);
    const key = d.toISOString().slice(0, 10);
    points.push({ day: key, hits: byDay.get(key) ?? 0 });
  }
  return points;
}

/**
 * Classify one rule's health from its pack's run history + the noise baseline.
 *
 * Precedence (most-specific first):
 *   1. ERRORED            — the rule's most recent run had a transpile/exec error.
 *   2. OVER_FIRING        — the rule is on the noise baseline (chronic hitter).
 *   3. UNDER_FIRING       — observed in ≥ UNDER_FIRING_MIN_RUNS runs, never hit.
 *   4. FIRING_AS_EXPECTED — hit on its most recent run, within the normal band.
 *   5. CLEAN              — most recent run was quiet.
 *
 * ``packRunsNewestFirst`` is that pack's runs already sorted newest-first.
 */
export function classifyRuleState(
  ruleId: string,
  packId: string,
  packRunsNewestFirst: HuntPackRun[],
  baselineIndex: Map<string, NoisyRule>,
): HuntRuleState {
  const observed = packRunsNewestFirst.filter((r) => r.rule_stats[ruleId] !== undefined);
  const latest = observed[0]?.rule_stats[ruleId];

  if (latest && latest.errors > 0) return "errored";
  if (baselineIndex.has(`${packId}:${ruleId}`)) return "over_firing";

  const totalHits = observed.reduce((sum, r) => sum + (r.rule_stats[ruleId]?.hits ?? 0), 0);
  if (observed.length >= UNDER_FIRING_MIN_RUNS && totalHits === 0) return "under_firing";
  if ((latest?.hits ?? 0) > 0) return "firing_as_expected";
  return "clean";
}

/** The most recent ``rule_stats`` entry for a rule across the pack's runs. */
function latestRuleStat(
  ruleId: string,
  packRunsNewestFirst: HuntPackRun[],
): HuntPackRunRuleStat | undefined {
  for (const run of packRunsNewestFirst) {
    const stat = run.rule_stats[ruleId];
    if (stat) return stat;
  }
  return undefined;
}

/** Roll the run history + baseline into the installed-packs view. */
export function buildInstalledPacks(
  runs: HuntPackRun[],
  baseline: NoiseBaseline | null,
): InstalledPack[] {
  const groups = groupRunsByPack(runs);
  const baselineIndex = indexBaseline(baseline);
  const packs: InstalledPack[] = [];

  for (const [packId, packRuns] of groups.entries()) {
    const lastRun = packRuns[0] ?? null;
    // Union of every rule id seen across the pack's runs.
    const ruleIds = new Set<string>();
    for (const run of packRuns) {
      for (const rid of Object.keys(run.rule_stats)) ruleIds.add(rid);
    }

    const rules: RuleStatus[] = [];
    for (const rid of ruleIds) {
      const observed = packRuns.filter((r) => r.rule_stats[rid] !== undefined);
      const stat = latestRuleStat(rid, packRuns);
      const totalHits = observed.reduce((sum, r) => sum + (r.rule_stats[rid]?.hits ?? 0), 0);
      const hitRuns = observed.filter((r) => (r.rule_stats[rid]?.hits ?? 0) > 0).length;
      rules.push({
        rule_id: rid,
        title: stat?.title ?? rid,
        state: classifyRuleState(rid, packId, packRuns, baselineIndex),
        last_hits: stat?.hits ?? 0,
        last_errors: stat?.errors ?? 0,
        runs_observed: observed.length,
        total_hits: totalHits,
        hit_rate: observed.length ? hitRuns / observed.length : 0,
        queries: stat?.queries ?? {},
      });
    }
    rules.sort((a, b) => a.title.localeCompare(b.title));

    packs.push({
      pack_id: packId,
      pack_name: lastRun?.pack_name ?? packId,
      pack_version: lastRun?.pack_version ?? "",
      backends: lastRun?.backends ?? [],
      last_run: lastRun,
      run_count: packRuns.length,
      hit_volume_30d: build30dHitVolume(packRuns),
      rules,
    });
  }

  packs.sort((a, b) => a.pack_name.localeCompare(b.pack_name));
  return packs;
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | null;
    if (body?.detail) return body.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

interface HuntPacksState {
  runs: HuntPackRun[];
  baseline: NoiseBaseline | null;
  /** Client-side muted packs (the per-org enable/disable store is deferred). */
  disabledPackIds: string[];
  selectedPackId: string | null;
  selectedRuleId: string | null;

  isLoading: boolean;
  error: string | null;

  /** Fetch the run history + noise baseline in parallel. */
  fetchAll: () => Promise<void>;
  /** Toggle a pack's local enabled state (view-only, not persisted). */
  togglePackEnabled: (packId: string) => void;
  selectPack: (packId: string | null) => void;
  selectRule: (ruleId: string | null) => void;
  clearError: () => void;
}

export const useHuntPacksStore = create<HuntPacksState>((set, get) => ({
  runs: [],
  baseline: null,
  disabledPackIds: [],
  selectedPackId: null,
  selectedRuleId: null,

  isLoading: false,
  error: null,

  fetchAll: async () => {
    set({ isLoading: true, error: null });
    try {
      // The baseline is advisory — its failure must not blank the whole page,
      // so tolerate it while still surfacing a hard pack-runs failure.
      const [runsResp, baselineResp] = await Promise.all([
        listPackRuns({ page: 1, page_size: RUN_PAGE_SIZE }),
        getNoiseBaseline().catch(() => null),
      ]);
      set({
        runs: runsResp.items ?? [],
        baseline: baselineResp,
        isLoading: false,
      });
    } catch (err) {
      set({
        isLoading: false,
        error: extractErrorMessage(err, "Failed to load hunt packs"),
      });
    }
  },

  togglePackEnabled: (packId) => {
    const disabled = new Set(get().disabledPackIds);
    if (disabled.has(packId)) disabled.delete(packId);
    else disabled.add(packId);
    set({ disabledPackIds: Array.from(disabled) });
  },

  selectPack: (packId) => set({ selectedPackId: packId, selectedRuleId: null }),
  selectRule: (ruleId) => set({ selectedRuleId: ruleId }),
  clearError: () => set({ error: null }),
}));
