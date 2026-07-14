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
const mockGetProposalPlan = vi.fn();
const mockExecuteProposalPlan = vi.fn();

vi.mock("@/api/pattern", () => ({
  listProposals: (...a: unknown[]) => mockListProposals(...a),
  dismissProposal: (...a: unknown[]) => mockDismissProposal(...a),
  snoozeProposal: (...a: unknown[]) => mockSnoozeProposal(...a),
  acceptProposal: (...a: unknown[]) => mockAcceptProposal(...a),
  getProposalPlan: (...a: unknown[]) => mockGetProposalPlan(...a),
  executeProposalPlan: (...a: unknown[]) => mockExecuteProposalPlan(...a),
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
    plansByProposal: {},
    planBusyId: null,
    planError: null,
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
  it("drops the proposal from the filtered view and decrements total", async () => {
    // Default filter is "proposed" — dismissing flips the proposal out of the
    // visible filter, so it leaves the list instead of being merged in place
    // (Codex #218 drop-behavior).
    const original = proposal({ id: "p1" });
    const updated: PatternHuntProposal = { ...original, state: "dismissed" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockDismissProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().dismiss("p1", { rationale: "not relevant" });

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p1");
    expect(inStore).toBeUndefined();
    expect(usePatternStore.getState().total).toBe(0);
    expect(usePatternStore.getState().isMutating).toBe(false);
  });

  it("merges the updated proposal in place when the filter is 'all'", async () => {
    const original = proposal({ id: "p1" });
    const updated: PatternHuntProposal = { ...original, state: "dismissed" };
    usePatternStore.setState({
      proposals: [original],
      total: 1,
      stateFilter: "all",
    });
    mockDismissProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().dismiss("p1", { rationale: "not relevant" });

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p1");
    expect(inStore?.state).toBe("dismissed");
    expect(usePatternStore.getState().total).toBe(1);
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
  it("drops the snoozed proposal from the filtered view", async () => {
    const original = proposal({ id: "p2" });
    const updated: PatternHuntProposal = { ...original, state: "snoozed" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockSnoozeProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().snooze("p2");

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p2");
    expect(inStore).toBeUndefined();
    expect(usePatternStore.getState().total).toBe(0);
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
  it("drops the accepted proposal from the filtered view", async () => {
    const original = proposal({ id: "p3" });
    const updated: PatternHuntProposal = { ...original, state: "accepted" };
    usePatternStore.setState({ proposals: [original], total: 1 });
    mockAcceptProposal.mockResolvedValueOnce(updated);

    await usePatternStore.getState().accept("p3");

    const inStore = usePatternStore
      .getState()
      .proposals.find((p: PatternHuntProposal) => p.id === "p3");
    expect(inStore).toBeUndefined();
    expect(usePatternStore.getState().total).toBe(0);
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

// --------------------------------------------------------------------------- //
// HuntPlan (#120 Phase C — fetchPlan / executePlan)
// --------------------------------------------------------------------------- //

import { ApiError } from "@/api/client";
import type { ProposalHuntPlan } from "@/types/pattern_hunt";

function huntPlan(overrides?: Partial<ProposalHuntPlan>): ProposalHuntPlan {
  return {
    id: "hplan_1",
    org_id: "org_default",
    proposal_id: "p1",
    status: "ready",
    plan: {
      id: "hunt_1",
      state: "ready",
      hypotheses: [{ ttp_id: "T1059.001", ttp_name: "PowerShell", priority: 0.9 }],
      ttp_entries: [
        {
          ttp_id: "T1059.001",
          ttp_name: "PowerShell",
          queries: { splunk: { backend: "splunk", query: "index=main" } },
        },
      ],
    },
    error: "",
    created_at: "2026-06-01T12:00:00Z",
    updated_at: "2026-06-01T12:00:00Z",
    ...overrides,
  };
}

describe("usePatternStore.fetchPlan", () => {
  it("stashes the plan keyed by proposal id", async () => {
    mockGetProposalPlan.mockResolvedValueOnce(huntPlan());

    await usePatternStore.getState().fetchPlan("p1");

    const state = usePatternStore.getState();
    expect(state.plansByProposal["p1"]?.status).toBe("ready");
    expect(state.planBusyId).toBeNull();
    expect(state.planError).toBeNull();
  });

  it("clears the entry silently on 404 (not accepted yet)", async () => {
    usePatternStore.setState({ plansByProposal: { p1: huntPlan() } });
    mockGetProposalPlan.mockRejectedValueOnce(new ApiError(404, "Not Found", null));

    await usePatternStore.getState().fetchPlan("p1");

    const state = usePatternStore.getState();
    expect(state.plansByProposal["p1"]).toBeUndefined();
    expect(state.planError).toBeNull();
  });

  it("surfaces non-404 errors", async () => {
    mockGetProposalPlan.mockRejectedValueOnce(new ApiError(500, "Server Error", null));

    await usePatternStore.getState().fetchPlan("p1");

    expect(usePatternStore.getState().planError).toBeTruthy();
    expect(usePatternStore.getState().planBusyId).toBeNull();
  });
});

describe("usePatternStore.executePlan", () => {
  it("updates the stashed plan and returns findings_created", async () => {
    const executed = huntPlan();
    executed.plan = {
      ...executed.plan!,
      state: "completed",
      last_run: {
        run_id: "hrun_1",
        started_at: "2026-06-01T12:00:00Z",
        completed_at: "2026-06-01T12:00:05Z",
        findings_created: 3,
        error_count: 0,
        per_ttp: { "T1059.001": { hits: 3, errors: [] } },
      },
    };
    mockExecuteProposalPlan.mockResolvedValueOnce({
      plan: executed,
      queued: false,
      findings_created: 3,
    });
    mockListProposals.mockResolvedValueOnce({ items: [], total: 0 });

    const created = await usePatternStore.getState().executePlan("p1");

    expect(created).toBe(3);
    const state = usePatternStore.getState();
    expect(state.plansByProposal["p1"]?.plan?.last_run?.findings_created).toBe(3);
    // Execution flips the proposal outcome server-side — the list refreshes.
    expect(mockListProposals).toHaveBeenCalled();
  });

  it("surfaces errors and re-throws", async () => {
    mockExecuteProposalPlan.mockRejectedValueOnce(
      new ApiError(409, "Conflict", { detail: "not ready" }),
    );

    await expect(usePatternStore.getState().executePlan("p1")).rejects.toBeTruthy();
    expect(usePatternStore.getState().planError).toBe("not ready");
    expect(usePatternStore.getState().planBusyId).toBeNull();
  });
});

describe("usePatternStore.accept plan hydration", () => {
  it("fetches the compiled plan after a successful accept", async () => {
    const original = proposal({ id: "p9" });
    const updated: PatternHuntProposal = { ...original, state: "accepted" };
    usePatternStore.setState({ proposals: [original], total: 1, stateFilter: "all" });
    mockAcceptProposal.mockResolvedValueOnce(updated);
    mockGetProposalPlan.mockResolvedValueOnce(huntPlan({ proposal_id: "p9" }));

    await usePatternStore.getState().accept("p9");

    expect(mockGetProposalPlan).toHaveBeenCalledWith("p9");
    expect(usePatternStore.getState().plansByProposal["p9"]?.status).toBe("ready");
  });
});
