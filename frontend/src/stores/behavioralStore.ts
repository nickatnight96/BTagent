/**
 * Behavioral Hunter Zustand store (#114 Phase B).
 *
 * State shape mirrors ``huntStore`` — paginated outlier list, intent-filter
 * tab, per-outlier mutation actions, and a client-side entity drift aggregator.
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import {
  feedbackBenign,
  listOutliers,
  promoteOutlier,
  setIntent,
} from "@/api/behavioral";
import type {
  BehavioralOutlier,
  EntityDriftSummary,
  IntentLabel,
  PromoteOutlierRequest,
  SetIntentRequest,
} from "@/types/behavioral";

// --------------------------------------------------------------------------- //
// Drift score helper
// --------------------------------------------------------------------------- //

/**
 * Build per-entity drift summaries from a flat outlier list.
 *
 * Drift score = outlier_count × max_cosine_distance.
 * See ``EntityDriftSummary`` JSDoc in ``types/behavioral.ts`` for rationale.
 *
 * The ``canonical_id`` returned is the one from the first outlier for that
 * entity — the backend doesn't return entity metadata in the outlier list,
 * so we fall back to ``entity_id`` when there's no richer label available.
 */
export function buildEntityDriftSummaries(
  outliers: BehavioralOutlier[],
): EntityDriftSummary[] {
  const byEntity = new Map<
    string,
    {
      canonical_id: string;
      kind: string;
      outliers: BehavioralOutlier[];
      max_cosine_distance: number;
    }
  >();

  for (const o of outliers) {
    const existing = byEntity.get(o.entity_id);
    if (existing) {
      existing.outliers.push(o);
      if (o.cosine_distance > existing.max_cosine_distance) {
        existing.max_cosine_distance = o.cosine_distance;
      }
    } else {
      byEntity.set(o.entity_id, {
        // entity_id is the stable key; canonical_id (the human-readable
        // label) comes from enrichment data the backend would embed.
        // The outlier row only carries entity_id, so we use entity_id as
        // the display name until the API exposes a richer entity lookup.
        canonical_id: o.entity_id,
        kind: "user", // conservative default; override when entity API lands
        outliers: [o],
        max_cosine_distance: o.cosine_distance,
      });
    }
  }

  const summaries: EntityDriftSummary[] = [];
  for (const [entity_id, data] of byEntity.entries()) {
    summaries.push({
      entity_id,
      canonical_id: data.canonical_id,
      kind: data.kind as EntityDriftSummary["kind"],
      outlier_count: data.outliers.length,
      max_cosine_distance: data.max_cosine_distance,
      drift_score: data.outliers.length * data.max_cosine_distance,
      outliers: data.outliers,
    });
  }

  // Sort descending by drift_score so the riskiest entity is first.
  return summaries.sort((a, b) => b.drift_score - a.drift_score);
}

// --------------------------------------------------------------------------- //
// Store types
// --------------------------------------------------------------------------- //

export type IntentFilter = IntentLabel | "all";

interface BehavioralState {
  outliers: BehavioralOutlier[];
  total: number;
  page: number;
  pageSize: number;
  intentFilter: IntentFilter;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Hydrate the outlier list from the backend. */
  fetchOutliers: (opts?: { page?: number }) => Promise<void>;
  setIntentFilter: (filter: IntentFilter) => void;
  setPage: (page: number) => void;

  /** Record an analyst intent verdict (benign / suspicious / malicious). */
  triageOutlier: (outlierId: string, body: SetIntentRequest) => Promise<void>;
  /**
   * Fold a benign outlier back into the entity baseline.
   * The caller must already have set intent_label=benign via ``triageOutlier``
   * before invoking this; the backend enforces it and returns 400 otherwise.
   */
  feedbackBenign: (outlierId: string) => Promise<void>;
  /** Promote an outlier to a HuntFinding; returns the new finding_id. */
  promote: (outlierId: string, body: PromoteOutlierRequest) => Promise<string>;

  clearError: () => void;
}

// --------------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------------- //

function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | null;
    if (body?.detail) return body.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

/** Merge an updated outlier back into the list in-place. */
function mergeOutlier(
  outliers: BehavioralOutlier[],
  updated: BehavioralOutlier,
): BehavioralOutlier[] {
  return outliers.map((o) => (o.id === updated.id ? updated : o));
}

// --------------------------------------------------------------------------- //
// Store
// --------------------------------------------------------------------------- //

export const useBehavioralStore = create<BehavioralState>((set, get) => ({
  outliers: [],
  total: 0,
  page: 1,
  pageSize: 50,
  intentFilter: "all",

  isLoading: false,
  isMutating: false,
  error: null,

  fetchOutliers: async (opts) => {
    const { intentFilter, page: currentPage, pageSize } = get();
    const page = opts?.page ?? currentPage;
    set({ isLoading: true, error: null });
    try {
      const resp = await listOutliers({
        intent_label: intentFilter === "all" ? null : intentFilter,
        page,
        page_size: pageSize,
      });
      set({
        outliers: resp.items ?? [],
        total: resp.total ?? 0,
        page,
        isLoading: false,
      });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load behavioral outliers");
      set({ isLoading: false, error: message });
    }
  },

  setIntentFilter: (filter) => {
    set({ intentFilter: filter, page: 1 });
  },

  setPage: (page) => {
    set({ page });
    void get().fetchOutliers({ page });
  },

  triageOutlier: async (outlierId, body) => {
    set({ isMutating: true, error: null });
    try {
      const updated = await setIntent(outlierId, body);
      set((s) => ({
        isMutating: false,
        outliers: mergeOutlier(s.outliers, updated),
      }));
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to set intent");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  feedbackBenign: async (outlierId) => {
    set({ isMutating: true, error: null });
    try {
      const updated = await feedbackBenign(outlierId);
      set((s) => ({
        isMutating: false,
        outliers: mergeOutlier(s.outliers, updated),
      }));
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to submit benign feedback");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  promote: async (outlierId, body) => {
    set({ isMutating: true, error: null });
    try {
      const resp = await promoteOutlier(outlierId, body);
      // Re-fetch the list so the promoted_to_finding_id shows up.
      await get().fetchOutliers();
      set({ isMutating: false });
      return resp.finding_id;
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to promote outlier");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),
}));
