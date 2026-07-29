/**
 * HuntPacks (Phase B) Zustand store (#112).
 *
 * The installed-packs view is composed from three hunt endpoints:
 *
 *   - ``GET /hunt/packs``         → the per-org pack store: every builtin pack
 *                                   with its install/enable state.
 *   - ``GET /hunt/pack-runs``     → the pack-run history (per-rule ``rule_stats``
 *                                   + hit volumes + last-run status).
 *   - ``GET /hunt/noise-baseline``→ the chronically-hitting (over-firing) rules.
 *
 * The catalog is keyed by the pack's **install key** (``pack_id``, the builtin
 * pack name the runner loads) while run history carries the pack's *manifest*
 * id, so the two are joined on ``manifest_pack_id``. A pack that has never run
 * still appears (from the catalog) so it can be enabled; a pack with runs but
 * no catalog entry (e.g. an ad-hoc CTI pack) still appears from its history.
 *
 * Enable/disable now **persists**: the switch calls
 * ``PUT /hunt/packs/{pack_id}`` and re-reads the catalog, so what the screen
 * shows is what the scheduled runner will run. It is RBAC-gated
 * (``huntpack:manage``, senior_analyst+); a 403 surfaces as an error rather
 * than silently flipping local state.
 *
 * The pure derivation helpers are exported so they can be unit-tested without a
 * running store (mirrors ``cloudStore`` / ``behavioralStore``).
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import { getNoiseBaseline, listHuntPacks, listPackRuns, setHuntPackEnabled } from "@/api/hunt";
import type {
  HuntPackCatalogEntry,
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

/** One installed pack, rolled up from its run history + the pack store. */
export interface InstalledPack {
  /** The manifest id run history uses (the view's stable key). */
  pack_id: string;
  pack_name: string;
  pack_version: string;
  backends: string[];
  /** Newest run for the pack, or null if it has never run. */
  last_run: HuntPackRun | null;
  run_count: number;
  hit_volume_30d: HitVolumePoint[];
  rules: RuleStatus[];
  /**
   * Install key for the enable/disable API (``PUT /hunt/packs/{install_key}``),
   * or null for a pack with run history but no catalog entry (e.g. an ad-hoc
   * CTI-merged pack) — those cannot be toggled.
   */
  install_key: string | null;
  /** Whether the scheduled runner will run this pack for the org. */
  enabled: boolean;
  rule_count: number;
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

/** Index the pack catalog by the manifest id run history carries. */
export function indexCatalog(
  catalog: HuntPackCatalogEntry[],
): Map<string, HuntPackCatalogEntry> {
  const map = new Map<string, HuntPackCatalogEntry>();
  for (const entry of catalog) map.set(entry.manifest_pack_id, entry);
  return map;
}

/** A catalog-only pack (never run yet) rendered as an empty installed pack. */
function catalogOnlyPack(entry: HuntPackCatalogEntry): InstalledPack {
  return {
    pack_id: entry.manifest_pack_id,
    pack_name: entry.name,
    pack_version: entry.version,
    backends: [],
    last_run: null,
    run_count: 0,
    hit_volume_30d: build30dHitVolume([]),
    rules: [],
    install_key: entry.pack_id,
    enabled: entry.enabled,
    rule_count: entry.rule_count,
  };
}

/** Roll the run history + baseline + pack catalog into the installed view. */
export function buildInstalledPacks(
  runs: HuntPackRun[],
  baseline: NoiseBaseline | null,
  catalog: HuntPackCatalogEntry[] = [],
): InstalledPack[] {
  const groups = groupRunsByPack(runs);
  const baselineIndex = indexBaseline(baseline);
  const catalogIndex = indexCatalog(catalog);
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

    const entry = catalogIndex.get(packId);
    packs.push({
      pack_id: packId,
      pack_name: lastRun?.pack_name ?? packId,
      pack_version: lastRun?.pack_version ?? "",
      backends: lastRun?.backends ?? [],
      last_run: lastRun,
      run_count: packRuns.length,
      hit_volume_30d: build30dHitVolume(packRuns),
      rules,
      install_key: entry?.pack_id ?? null,
      // A pack with history but no catalog entry (ad-hoc CTI pack) is not
      // schedulable, so it reads as enabled rather than falsely "off".
      enabled: entry ? entry.enabled : true,
      rule_count: entry?.rule_count ?? rules.length,
    });
  }

  // Packs that ship but have never run still belong on the screen — otherwise
  // there is no way to enable one.
  for (const entry of catalog) {
    if (!groups.has(entry.manifest_pack_id)) packs.push(catalogOnlyPack(entry));
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
  /** The per-org pack store: every builtin pack + its enable state. */
  catalog: HuntPackCatalogEntry[];
  selectedPackId: string | null;
  selectedRuleId: string | null;
  /** Install key currently being written (drives the switch's pending state). */
  togglingPackId: string | null;

  isLoading: boolean;
  error: string | null;

  /** Fetch the pack catalog + run history + noise baseline in parallel. */
  fetchAll: () => Promise<void>;
  /**
   * Persist a pack's enabled state for the org (``PUT /hunt/packs/{key}``).
   * ``installKey`` is the catalog's ``pack_id``; a pack without one (no catalog
   * entry) is not schedulable and is ignored.
   */
  togglePackEnabled: (installKey: string | null, enabled: boolean) => Promise<void>;
  selectPack: (packId: string | null) => void;
  selectRule: (ruleId: string | null) => void;
  clearError: () => void;
}

export const useHuntPacksStore = create<HuntPacksState>((set, get) => ({
  runs: [],
  baseline: null,
  catalog: [],
  selectedPackId: null,
  selectedRuleId: null,
  togglingPackId: null,

  isLoading: false,
  error: null,

  fetchAll: async () => {
    set({ isLoading: true, error: null });
    try {
      // The baseline and the catalog are advisory reads — their failure must
      // not blank the whole page, so tolerate them while still surfacing a
      // hard pack-runs failure.
      const [runsResp, baselineResp, catalogResp] = await Promise.all([
        listPackRuns({ page: 1, page_size: RUN_PAGE_SIZE }),
        getNoiseBaseline().catch(() => null),
        listHuntPacks().catch(() => null),
      ]);
      set({
        runs: runsResp.items ?? [],
        baseline: baselineResp,
        catalog: catalogResp?.items ?? [],
        isLoading: false,
      });
    } catch (err) {
      set({
        isLoading: false,
        error: extractErrorMessage(err, "Failed to load hunt packs"),
      });
    }
  },

  togglePackEnabled: async (installKey, enabled) => {
    if (!installKey) return;
    set({ togglingPackId: installKey, error: null });
    try {
      const updated = await setHuntPackEnabled(installKey, enabled);
      // Splice the server's answer in rather than trusting the optimistic
      // value — the backend owns the resolution semantics.
      set({
        catalog: get().catalog.map((e) => (e.pack_id === updated.pack_id ? updated : e)),
        togglingPackId: null,
      });
    } catch (err) {
      set({
        togglingPackId: null,
        error: extractErrorMessage(
          err,
          `Failed to ${enabled ? "enable" : "disable"} '${installKey}'`,
        ),
      });
    }
  },

  selectPack: (packId) => set({ selectedPackId: packId, selectedRuleId: null }),
  selectRule: (ruleId) => set({ selectedRuleId: ruleId }),
  clearError: () => set({ error: null }),
}));
