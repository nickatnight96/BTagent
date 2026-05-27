import { create } from "zustand";
import type {
  CreateSuppressionRequest,
  HuntFinding,
  HuntFindingCluster,
  SuppressionRule,
} from "@/types/hunt";
import {
  createSuppression,
  listFindings,
  listSuppressions,
  promoteFindings,
  suppressFinding,
} from "@/api/hunt";

interface HuntState {
  clusters: HuntFindingCluster[];
  findings: HuntFinding[];
  suppressions: SuppressionRule[];
  totalClusters: number;
  totalFindings: number;
  includeSuppressed: boolean;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Findings selected for bulk promotion. */
  selectedFindingIds: string[];

  fetchInbox: () => Promise<void>;
  fetchSuppressions: () => Promise<void>;
  toggleIncludeSuppressed: () => Promise<void>;
  toggleSelected: (findingId: string) => void;
  clearSelection: () => void;
  suppress: (findingId: string, body: CreateSuppressionRequest) => Promise<void>;
  createRule: (body: CreateSuppressionRequest) => Promise<void>;
  promote: (findingIds: string[], title?: string) => Promise<string>;
  clearError: () => void;
}

/** Findings grouped by their cluster id (clusterless findings under ""). */
export function groupFindingsByCluster(
  findings: HuntFinding[],
): Record<string, HuntFinding[]> {
  return findings.reduce<Record<string, HuntFinding[]>>((acc, f) => {
    const key = f.cluster_id ?? "";
    (acc[key] ??= []).push(f);
    return acc;
  }, {});
}

export const useHuntStore = create<HuntState>((set, get) => ({
  clusters: [],
  findings: [],
  suppressions: [],
  totalClusters: 0,
  totalFindings: 0,
  includeSuppressed: false,

  isLoading: false,
  isMutating: false,
  error: null,

  selectedFindingIds: [],

  fetchInbox: async () => {
    set({ isLoading: true, error: null });
    try {
      const resp = await listFindings({ include_suppressed: get().includeSuppressed });
      set({
        clusters: resp.clusters ?? [],
        findings: resp.findings ?? [],
        totalClusters: resp.total_clusters ?? 0,
        totalFindings: resp.total_findings ?? 0,
        isLoading: false,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load hunt inbox";
      set({ isLoading: false, error: message });
    }
  },

  fetchSuppressions: async () => {
    try {
      const resp = await listSuppressions();
      set({ suppressions: resp.items ?? [] });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load suppressions";
      set({ error: message });
    }
  },

  toggleIncludeSuppressed: async () => {
    set({ includeSuppressed: !get().includeSuppressed });
    await get().fetchInbox();
  },

  toggleSelected: (findingId) => {
    const current = get().selectedFindingIds;
    set({
      selectedFindingIds: current.includes(findingId)
        ? current.filter((id) => id !== findingId)
        : [...current, findingId],
    });
  },

  clearSelection: () => set({ selectedFindingIds: [] }),

  suppress: async (findingId, body) => {
    set({ isMutating: true, error: null });
    try {
      await suppressFinding(findingId, body);
      await get().fetchInbox();
      set({ isMutating: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to suppress finding";
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  createRule: async (body) => {
    set({ isMutating: true, error: null });
    try {
      await createSuppression(body);
      await Promise.all([get().fetchInbox(), get().fetchSuppressions()]);
      set({ isMutating: false });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create suppression";
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  promote: async (findingIds, title) => {
    set({ isMutating: true, error: null });
    try {
      const resp = await promoteFindings(findingIds, title);
      set({ isMutating: false, selectedFindingIds: [] });
      await get().fetchInbox();
      return resp.investigation_id;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to promote findings";
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),
}));
