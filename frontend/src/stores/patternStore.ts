/**
 * Pattern Hunt Zustand store (#120 Phase B).
 *
 * State shape mirrors ``behavioralStore`` — paginated proposal list,
 * state-filter tab, per-proposal mutation actions (dismiss / snooze / accept).
 */

import { create } from "zustand";
import { ApiError } from "@/api/client";
import {
  acceptProposal,
  dismissProposal,
  listProposals,
  snoozeProposal,
} from "@/api/pattern";
import type {
  ActionRequest,
  PatternHuntProposal,
  ProposalFilter,
} from "@/types/pattern_hunt";

// --------------------------------------------------------------------------- //
// Store types
// --------------------------------------------------------------------------- //

interface PatternState {
  proposals: PatternHuntProposal[];
  total: number;
  page: number;
  pageSize: number;
  /** Active state-filter tab. "all" = no state filter sent to the backend. */
  stateFilter: ProposalFilter;

  isLoading: boolean;
  isMutating: boolean;
  error: string | null;

  /** Hydrate the proposal list from the backend. */
  fetchProposals: (opts?: { page?: number }) => Promise<void>;
  setStateFilter: (filter: ProposalFilter) => void;
  setPage: (page: number) => void;

  /** Dismiss a proposal (down-weights similar future surfacing). */
  dismiss: (proposalId: string, body?: ActionRequest) => Promise<void>;
  /** Snooze a proposal (reversibly down-weights similar future surfacing). */
  snooze: (proposalId: string, body?: ActionRequest) => Promise<void>;
  /**
   * Accept a proposal — marks the analyst's intent to run this hunt.
   * HuntPlan generation is deferred to Phase C.
   */
  accept: (proposalId: string, body?: ActionRequest) => Promise<void>;

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

/**
 * Merge an updated proposal back into the list. When ``stateFilter`` is set
 * to a specific state (the actionable ``proposed`` queue is the default), a
 * mutation that flips the proposal out of that state DROPS it from the list
 * — Codex #218 P2: otherwise the actionable queue showed dismissed / accepted
 * items until the next poll/refresh even though the backend filter would no
 * longer return them.
 */
function mergeProposal(
  proposals: PatternHuntProposal[],
  updated: PatternHuntProposal,
  stateFilter: ProposalFilter,
): PatternHuntProposal[] {
  if (stateFilter !== "all" && updated.state !== stateFilter) {
    // Triaged out of the visible filter — drop it from the list.
    return proposals.filter((p) => p.id !== updated.id);
  }
  return proposals.map((p) => (p.id === updated.id ? updated : p));
}

// --------------------------------------------------------------------------- //
// Store
// --------------------------------------------------------------------------- //

export const usePatternStore = create<PatternState>((set, get) => ({
  proposals: [],
  total: 0,
  page: 1,
  pageSize: 50,
  stateFilter: "proposed",

  isLoading: false,
  isMutating: false,
  error: null,

  fetchProposals: async (opts) => {
    const { stateFilter, page: currentPage, pageSize } = get();
    const page = opts?.page ?? currentPage;
    set({ isLoading: true, error: null });
    try {
      const resp = await listProposals({
        state: stateFilter === "all" ? null : stateFilter,
        page,
        page_size: pageSize,
      });
      set({
        proposals: resp.items ?? [],
        total: resp.total ?? 0,
        page,
        isLoading: false,
      });
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to load pattern-hunt proposals");
      set({ isLoading: false, error: message });
    }
  },

  setStateFilter: (filter) => {
    set({ stateFilter: filter, page: 1 });
  },

  setPage: (page) => {
    set({ page });
    void get().fetchProposals({ page });
  },

  dismiss: async (proposalId, body) => {
    set({ isMutating: true, error: null });
    try {
      const updated = await dismissProposal(proposalId, body);
      set((s) => ({
        isMutating: false,
        proposals: mergeProposal(s.proposals, updated, s.stateFilter),
        // ``total`` reflects what the backend would now return for the current
        // filter; decrement when an item leaves the filtered view (Codex #218).
        total:
          s.stateFilter !== "all" && updated.state !== s.stateFilter
            ? Math.max(0, s.total - 1)
            : s.total,
      }));
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to dismiss proposal");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  snooze: async (proposalId, body) => {
    set({ isMutating: true, error: null });
    try {
      const updated = await snoozeProposal(proposalId, body);
      set((s) => ({
        isMutating: false,
        proposals: mergeProposal(s.proposals, updated, s.stateFilter),
        // ``total`` reflects what the backend would now return for the current
        // filter; decrement when an item leaves the filtered view (Codex #218).
        total:
          s.stateFilter !== "all" && updated.state !== s.stateFilter
            ? Math.max(0, s.total - 1)
            : s.total,
      }));
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to snooze proposal");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  accept: async (proposalId, body) => {
    set({ isMutating: true, error: null });
    try {
      const updated = await acceptProposal(proposalId, body);
      set((s) => ({
        isMutating: false,
        proposals: mergeProposal(s.proposals, updated, s.stateFilter),
        // ``total`` reflects what the backend would now return for the current
        // filter; decrement when an item leaves the filtered view (Codex #218).
        total:
          s.stateFilter !== "all" && updated.state !== s.stateFilter
            ? Math.max(0, s.total - 1)
            : s.total,
      }));
    } catch (err) {
      const message = extractErrorMessage(err, "Failed to accept proposal");
      set({ isMutating: false, error: message });
      throw err;
    }
  },

  clearError: () => set({ error: null }),
}));
