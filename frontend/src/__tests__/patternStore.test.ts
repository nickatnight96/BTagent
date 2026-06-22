/**
 * Unit tests for the patternStore Zustand store (#120 Phase B).
 *
 * The store is tested via its public surface (fetchProposals, dismiss,
 * snooze, accept) with mocked API calls — mirrors the shape of
 * ``behavioralStore.test.ts``.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import type { PatternHuntProposal } from "@/types/pattern_hunt";

// --------------------------------------------------------------------------- //
// Fixture helpers
// --------------------------------------------------------------------------- //

function proposal(
  overrides: Partial<PatternHuntProposal> & { id: string },
): PatternHuntProposal {
  return {
    org_id: "org_default",
    cluster_id: `cl_${overrides.id}`,
    score: 0.5,
    hunt_input: {
      adversaries: [],
      ttps: ["T1059.001"],
      iocs: [],
      scope: {
        environments: [],
        hosts: [],
        date_from: null,
        date_to: null,
        backends: [],
      },
    },
    rationale: `Test rationale for ${overrides.id}`,
    state: "proposed",
    outcome: null,
    created_at: "2026-06-01T12:00:00Z",
    updated_at: "2026-06-01T12:00:00Z",
    ...overrides,
  };
}

// --------------------------------------------------------------------------- //
// API mocks
// --------------------------------------------------------------------------- //

const mockListProposals = vi.fn();
const mockDismissProposal = vi.fn();
const mockSnoozeProposal = vi.fn();
const mockAcceptProposal = vi.fn();

vi.mock("@/api/pattern", () => ({
  listProposals: (...a: unknown[]) => mockListProposals(...a),
  dismissProposal: (...a: unknown[]) => mockDismissProposal(...a),
  snoozeProposal: (...a: unknown[]) => mockSnoozeProposal(...a),
  acceptProposal: (...a: unknown[]) => mockAcceptProposal(...a),
}));

import { usePatternStore } from "@/stores/patternStore";

beforeEach(() => {
  vi.clearAllMocks();
  // Reset the store between tests.
  usePatternStore.setState({
    proposals: [],
    total: 0,
    page: 1,
    pageSize: 50,
    stateFilter: "proposed",
    isLoading: false,
    isMutating: false,
    error: null,
  });
});

// --------------------------------------------------------------------------- //
// fetchProposals
// --------------------------------------------------------------------------- //

describe("usePatternStore.fetchProposals", () => {
  it("populates proposals and total from the API response", async () => {
    const items = [proposal({ id: "p1" })];
    mockListProposals.mockResolvedValueOnce({ items, total: 1 });

    await usePatternStore.getState().fetchProposals();

    const { proposals, total, isLoading, error } = usePatternStore.getState();
    expect(proposals).toEqual(items);
    expect(total).toBe(1);
    expect(isLoading).toBe(false);
    expect(error).toBeNull();
  });

  it("sets error state on API failure", async () => {
    mockListProposals.mockRejectedValueOnce(new Error("network error"));

    await usePatternStore.getState().fetchProposals();

    expect(usePatternStore.getState().error).toBeTruthy();
    expect(usePatternStore.getState().isLoading).toBe(false);
  });

  it("passes state param when filter is not 'all'", async () => {
    mockListProposals.mockResolvedValueOnce({ items: [], total: 0 });
    usePatternStore.setState({ stateFilter: "dismissed" });

    await usePatternStore.getState().fetchProposals();

    expect(mockListProposals).toHaveBeenCalledWith(
      expect.objectContaining({ state: "dismissed" }),
    );
  });

  it("passes null state param when filter is 'all'", async () => {
    mockListProposals.mockResolvedValueOnce({ items: [], total: 0 });
    usePatternStore.setState({ stateFilter: "all" });

    await usePatternStore.getState().fetchProposals();

    expect(mockListProposals).toHaveBeenCalledWith(
      expect.objectContaining({ state: null }),
    );
  });

  it("uses the provided page override", async () => {
    mockListProposals.mockResolvedValueOnce({ items: [], total: 0 });

    await usePatternStore.getState().fetchProposals({ page: 3 });

    expect(usePatternStore.getState().page).toBe(3);
  });
});

// --------------------------------------------------------------------------- //
// dismiss
// --------------------------------------------------------------------------- //

describe("usePatternStore.dismiss", () => {
  it("merges the updated proposal into the list on success", async () => {
    const original = proposal({ id: "p1" });
    const updated: PatternHuntProposal = { ...original, state: "dismissed" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockDismissProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().dismiss("p1", { rationale: "not relevant" });

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p1");
    expect(inStore?.state).toBe("dismissed");
    expect(usePatternStore.getState().isMutating).toBe(false);
  });

  it("surfaces error and re-throws on API failure", async () => {
    mockDismissProposal.mockRejectedValueOnce(new Error("500"));
    usePatternStore.setState({ proposals: [proposal({ id: "p1" })] });

    await expect(
      usePatternStore.getState().dismiss("p1"),
    ).rejects.toBeTruthy();

    expect(usePatternStore.getState().error).toBeTruthy();
    expect(usePatternStore.getState().isMutating).toBe(false);
  });
});

// --------------------------------------------------------------------------- //
// snooze
// --------------------------------------------------------------------------- //

describe("usePatternStore.snooze", () => {
  it("merges the updated proposal into the list on success", async () => {
    const original = proposal({ id: "p2" });
    const updated: PatternHuntProposal = { ...original, state: "snoozed" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockSnoozeProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().snooze("p2");

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p2");
    expect(inStore?.state).toBe("snoozed");
  });

  it("sets error on failure", async () => {
    mockSnoozeProposal.mockRejectedValueOnce(new Error("503"));
    usePatternStore.setState({ proposals: [proposal({ id: "p2" })] });

    await expect(usePatternStore.getState().snooze("p2")).rejects.toBeTruthy();
    expect(usePatternStore.getState().error).toBeTruthy();
  });
});

// --------------------------------------------------------------------------- //
// accept
// --------------------------------------------------------------------------- //

describe("usePatternStore.accept", () => {
  it("merges the accepted proposal into the list", async () => {
    const original = proposal({ id: "p3" });
    const updated: PatternHuntProposal = { ...original, state: "accepted" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockAcceptProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().accept("p3");

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p3");
    expect(inStore?.state).toBe("accepted");
    expect(usePatternStore.getState().isMutating).toBe(false);
  });
});

// --------------------------------------------------------------------------- //
// setStateFilter / clearError
// --------------------------------------------------------------------------- //

describe("usePatternStore.setStateFilter", () => {
  it("resets page to 1 when the filter changes", () => {
    usePatternStore.setState({ page: 4, stateFilter: "proposed" });
    usePatternStore.getState().setStateFilter("dismissed");
    expect(usePatternStore.getState().stateFilter).toBe("dismissed");
    expect(usePatternStore.getState().page).toBe(1);
  });
});

describe("usePatternStore.clearError", () => {
  it("clears the error field", () => {
    usePatternStore.setState({ error: "something broke" });
    usePatternStore.getState().clearError();
    expect(usePatternStore.getState().error).toBeNull();
  });
});
