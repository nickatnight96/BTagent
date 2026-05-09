import { create } from "zustand";
import type {
  MitreTechnique,
  MitreTactic,
  CoverageData,
  NavigatorLayer,
} from "@/types/mitre";
import {
  listTechniques,
  listTactics as fetchTacticsApi,
  getCoverage as getCoverageApi,
  getTechnique,
  searchTTPs,
  exportNavigator as exportNavigatorApi,
} from "@/api/mitre";

interface MitreState {
  techniques: MitreTechnique[];
  tactics: MitreTactic[];
  coverage: CoverageData | null;
  selectedTechnique: MitreTechnique | null;
  investigationFilter: string | null;
  isLoading: boolean;
  error: string | null;
  searchQuery: string;

  fetchTechniques: (params?: { tactic_id?: string; search?: string }) => Promise<void>;
  fetchTactics: () => Promise<void>;
  fetchCoverage: (investigationId?: string) => Promise<void>;
  searchTechniques: (query: string) => Promise<void>;
  selectTechnique: (technique: MitreTechnique | null) => void;
  fetchTechnique: (id: string) => Promise<void>;
  setInvestigationFilter: (id: string | null) => void;
  exportNavigator: (investigationId?: string) => Promise<void>;
  clearError: () => void;
}

export const useMitreStore = create<MitreState>((set, get) => ({
  techniques: [],
  tactics: [],
  coverage: null,
  selectedTechnique: null,
  investigationFilter: null,
  isLoading: false,
  error: null,
  searchQuery: "",

  fetchTechniques: async (params) => {
    set({ isLoading: true, error: null });
    try {
      const response = await listTechniques({
        ...params,
        page_size: 500,
      });
      set({ techniques: response.items, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch techniques";
      set({ isLoading: false, error: message });
    }
  },

  fetchTactics: async () => {
    set({ isLoading: true, error: null });
    try {
      const tactics = await fetchTacticsApi();
      set({ tactics, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch tactics";
      set({ isLoading: false, error: message });
    }
  },

  fetchCoverage: async (investigationId) => {
    set({ isLoading: true, error: null });
    try {
      const coverage = await getCoverageApi(investigationId);
      set({ coverage, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch coverage data";
      set({ isLoading: false, error: message });
    }
  },

  searchTechniques: async (query: string) => {
    set({ isLoading: true, error: null, searchQuery: query });
    try {
      if (!query.trim()) {
        await get().fetchTechniques();
        return;
      }
      const response = await searchTTPs(query);
      set({ techniques: response.items, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to search techniques";
      set({ isLoading: false, error: message });
    }
  },

  selectTechnique: (technique) => {
    set({ selectedTechnique: technique });
  },

  fetchTechnique: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const technique = await getTechnique(id);
      set({ selectedTechnique: technique, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch technique";
      set({ isLoading: false, error: message });
    }
  },

  setInvestigationFilter: (id) => {
    set({ investigationFilter: id });
    void get().fetchCoverage(id ?? undefined);
  },

  exportNavigator: async (investigationId) => {
    set({ isLoading: true, error: null });
    try {
      const layer: NavigatorLayer = await exportNavigatorApi(investigationId);
      const blob = new Blob([JSON.stringify(layer, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `attack_navigator_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      set({ isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to export navigator layer";
      set({ isLoading: false, error: message });
    }
  },

  clearError: () => set({ error: null }),
}));
