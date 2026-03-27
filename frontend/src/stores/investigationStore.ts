import { create } from "zustand";
import type { Investigation } from "@/types/investigation";
import type { InvestigationStatus } from "@/types/config";
import { listInvestigations, getInvestigation } from "@/api/investigations";

interface InvestigationState {
  investigations: Investigation[];
  currentInvestigation: Investigation | null;
  isLoading: boolean;
  error: string | null;

  fetchInvestigations: (params?: {
    status?: string;
    severity?: string;
    search?: string;
  }) => Promise<void>;
  fetchInvestigation: (id: string) => Promise<void>;
  upsertInvestigation: (investigation: Investigation) => void;
  updateStatus: (id: string, status: InvestigationStatus) => void;
  updateCost: (id: string, costUsd: number, tokenCount: number) => void;
  setCurrentInvestigation: (investigation: Investigation | null) => void;
  clearError: () => void;
}

export const useInvestigationStore = create<InvestigationState>((set, get) => ({
  investigations: [],
  currentInvestigation: null,
  isLoading: false,
  error: null,

  fetchInvestigations: async (params) => {
    set({ isLoading: true, error: null });
    try {
      const response = await listInvestigations(params);
      set({ investigations: response.items, isLoading: false });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch investigations";
      set({ isLoading: false, error: message });
    }
  },

  fetchInvestigation: async (id: string) => {
    set({ isLoading: true, error: null });
    try {
      const investigation = await getInvestigation(id);
      set({ currentInvestigation: investigation, isLoading: false });
      // Also update in the list
      get().upsertInvestigation(investigation);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch investigation";
      set({ isLoading: false, error: message });
    }
  },

  upsertInvestigation: (investigation: Investigation) => {
    set((state) => {
      const index = state.investigations.findIndex(
        (inv) => inv.id === investigation.id,
      );
      const updated = [...state.investigations];
      if (index >= 0) {
        updated[index] = investigation;
      } else {
        updated.unshift(investigation);
      }
      return {
        investigations: updated,
        currentInvestigation:
          state.currentInvestigation?.id === investigation.id
            ? investigation
            : state.currentInvestigation,
      };
    });
  },

  updateStatus: (id: string, status: InvestigationStatus) => {
    set((state) => ({
      investigations: state.investigations.map((inv) =>
        inv.id === id ? { ...inv, status } : inv,
      ),
      currentInvestigation:
        state.currentInvestigation?.id === id
          ? { ...state.currentInvestigation, status }
          : state.currentInvestigation,
    }));
  },

  updateCost: (id: string, costUsd: number, tokenCount: number) => {
    set((state) => ({
      investigations: state.investigations.map((inv) =>
        inv.id === id ? { ...inv, cost_usd: costUsd, token_count: tokenCount } : inv,
      ),
      currentInvestigation:
        state.currentInvestigation?.id === id
          ? { ...state.currentInvestigation, cost_usd: costUsd, token_count: tokenCount }
          : state.currentInvestigation,
    }));
  },

  setCurrentInvestigation: (investigation) => {
    set({ currentInvestigation: investigation });
  },

  clearError: () => set({ error: null }),
}));
