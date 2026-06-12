import { create } from "zustand";
import { ApiError } from "@/api/client";
import type {
  CreateSuppressionRequest,
  HuntFinding,
  HuntFindingCluster,
  PromoteClusterRequest,
  SuppressionRule,
  SuppressClusterRequest,
} from "@/types/hunt";
import {
  createSuppression,
  listFindings,
  listSuppressions,
  promoteCluster,
  promoteFindings,
  suppressCluster,
  suppressFinding,
} from "@/api/hunt";

/** The active tab in the triage inbox. */
export type InboxTab = "active" | "suppressed" | "promoted";

interface HuntState {
  clusters: HuntFindingCluster[];
  findings: HuntFinding[];
  suppressions: SuppressionRule[];
  totalClusters: number;
  totalFindings: number;
  includeSuppressed: boolean;
  activeTab: InboxTab;
  page: number;
  pageSize: number;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Findings selected for bulk promotion. */
  selectedFindingIds: string[];

  fetchInbox: (opts?: { page?: number }) => Promise<void>;
  fetchSuppressions: () => Promise<void>;
  setTab: (tab: InboxTab) => void;
  setPage: (page: number) => void;
  toggleIncludeSuppressed: () => Promise<void>;
  toggleSelected: (findingId: string) => void;
  clearSelection: () => void;
  suppress: (findingId: string, body: CreateSuppressionRequest) => Promise<void>;
  suppressCluster: (clusterId: string, body: SuppressClusterRequest) => Promise<void>;
  promoteCluster: (clusterId: string, body: PromoteClusterRequest) => Promise<string>;
  createRule: (body: CreateSuppressionRequest) => Promise<void>;
  promote: (findingIds: string[], title?: string) => Promise<string>;
  clearError: () => void;
}

/** Extract a human-readable message from an error, preferring body.detail for ApiError. */
function extractErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | null;
    if (body?.detail) return body.detail;
  }
  if (err instanceof Error) return err.message;
  return fallback;
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
  activeTab: "active",
  page: 1,
  pageSize: 50,

  isLoading: false,
  isMutating: false,
  error: null,

  selectedFindingIds: [],

  fetchInbox: async (opts) => {
    const { includeSuppressed, page: currentPage, pageSize } = get();
    const page = opts?.page ?? currentPage;
    set({ isLoading: true, error: null });
    try {
      const resp = await listFindings({
        include_suppressed: includeSuppressed,
        page,
        page_size: pageSize,
      });
      set({
        clusters: resp.clusters ?? [],
        findings: resp.findings ?? [],
        totalClusters: resp.total_clusters ?? 0,
        totalFindings: resp.total_findings ?? 0,
        page,
        isLoading: false,
      });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load hunt inbox");
      set({ isLoading: false, error: message });
    }
  },

  fetchSuppressions: async () => {
    try {
      const resp = await listSuppressions();
      set({ suppressions: resp.items ?? [] });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load suppressions");
      set({ error: message });
    }
  },

  setTab: (tab) => {
    const includeSuppressed = tab === "suppressed";
    set({ activeTab: tab, includeSuppressed, page: 1 });
  },

  setPage: (page) => {
    set({ page });
    void get().fetchInbox({ page });
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
      const message = extractErrorMessage(err, "Failed to suppress finding");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  suppressCluster: async (clusterId, body) => {
    set({ isMutating: true, error: null });
    try {
      await suppressCluster(clusterId, body);
      await get().fetchInbox();
      set({ isMutating: false });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to suppress cluster");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  promoteCluster: async (clusterId, body) => {
    set({ isMutating: true, error: null });
    try {
      const resp = await promoteCluster(clusterId, body);
      set({ isMutating: false });
      await get().fetchInbox();
      return resp.investigation_id;
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to promote cluster");
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
      const message = extractErrorMessage(err, "Failed to create suppression");
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
      const message = extractErrorMessage(err, "Failed to promote findings");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),
}));
