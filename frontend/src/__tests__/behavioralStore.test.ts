/**
 * Unit tests for the behavioralStore helpers and Zustand store (#114 Phase B).
 *
 * The store itself is tested via its public surface (fetchOutliers,
 * triageOutlier, promote) with mocked API calls — same pattern as
 * ``huntStore.test.ts``.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { buildEntityDriftSummaries } from "@/stores/behavioralStore";
import type { BehavioralOutlier } from "@/types/behavioral";
// NOTE: BehavioralOutlier is also used as an explicit parameter type annotation
// inside test callbacks where TypeScript cannot infer it from the mock return
// type (strict mode requires explicit annotations in those positions).

// --------------------------------------------------------------------------- //
// Fixture helpers
// --------------------------------------------------------------------------- //

function outlier(
  overrides: Partial<BehavioralOutlier> & { id: string; entity_id: string },
): BehavioralOutlier {
  return {
    org_id: "org_default",
    profile_type: "cmdline_embedding",
    event_id: `evt_${overrides.id}`,
    cosine_distance: 0.5,
    frequency_rank: 3,
    raw_event_excerpt: "",
    intent_label: null,
    intent_rationale: null,
    promoted_to_finding_id: null,
    created_at: "2026-06-01T12:00:00Z",
    ...overrides,
  };
}

// --------------------------------------------------------------------------- //
// buildEntityDriftSummaries
// --------------------------------------------------------------------------- //

describe("buildEntityDriftSummaries", () => {
  it("returns an empty array for no outliers", () => {
    expect(buildEntityDriftSummaries([])).toEqual([]);
  });

  it("aggregates outliers by entity_id", () => {
    const summaries = buildEntityDriftSummaries([
      outlier({ id: "a", entity_id: "ent_1" }),
      outlier({ id: "b", entity_id: "ent_1" }),
      outlier({ id: "c", entity_id: "ent_2" }),
    ]);
    expect(summaries).toHaveLength(2);
    const ent1 = summaries.find((s) => s.entity_id === "ent_1");
    expect(ent1?.outlier_count).toBe(2);
    const ent2 = summaries.find((s) => s.entity_id === "ent_2");
    expect(ent2?.outlier_count).toBe(1);
  });

  it("tracks max_cosine_distance per entity", () => {
    const summaries = buildEntityDriftSummaries([
      outlier({ id: "a", entity_id: "ent_1", cosine_distance: 0.3 }),
      outlier({ id: "b", entity_id: "ent_1", cosine_distance: 0.9 }),
      outlier({ id: "c", entity_id: "ent_1", cosine_distance: 0.5 }),
    ]);
    // Single entity — index 0 is guaranteed
    expect(summaries[0]!.max_cosine_distance).toBeCloseTo(0.9);
  });

  it("computes drift_score = count × max_cosine_distance", () => {
    const summaries = buildEntityDriftSummaries([
      outlier({ id: "a", entity_id: "ent_1", cosine_distance: 0.4 }),
      outlier({ id: "b", entity_id: "ent_1", cosine_distance: 0.8 }),
    ]);
    // 2 outliers × max(0.4, 0.8) = 2 × 0.8 = 1.6
    expect(summaries[0]!.drift_score).toBeCloseTo(1.6);
  });

  it("sorts entities by drift_score descending", () => {
    const summaries = buildEntityDriftSummaries([
      // ent_low: 1 × 0.2 = 0.2
      outlier({ id: "a", entity_id: "ent_low", cosine_distance: 0.2 }),
      // ent_high: 3 × 0.9 = 2.7
      outlier({ id: "b", entity_id: "ent_high", cosine_distance: 0.9 }),
      outlier({ id: "c", entity_id: "ent_high", cosine_distance: 0.5 }),
      outlier({ id: "d", entity_id: "ent_high", cosine_distance: 0.7 }),
    ]);
    expect(summaries[0]!.entity_id).toBe("ent_high");
    expect(summaries[1]!.entity_id).toBe("ent_low");
  });

  it("preserves individual outlier objects inside each summary", () => {
    const o1 = outlier({ id: "a", entity_id: "ent_1" });
    const o2 = outlier({ id: "b", entity_id: "ent_1" });
    const [summary] = buildEntityDriftSummaries([o1, o2]);
    expect(summary!.outliers).toContain(o1);
    expect(summary!.outliers).toContain(o2);
  });

  it("uses entity_id as canonical_id fallback when no richer label is available", () => {
    const [summary] = buildEntityDriftSummaries([
      outlier({ id: "a", entity_id: "ent_abc123" }),
    ]);
    expect(summary!.canonical_id).toBe("ent_abc123");
  });
});

// --------------------------------------------------------------------------- //
// Store integration (light — just verifies the store shape / API wiring)
// --------------------------------------------------------------------------- //

const mockListOutliers = vi.fn();
const mockSetIntent = vi.fn();
const mockFeedbackBenign = vi.fn();
const mockPromoteOutlier = vi.fn();

vi.mock("@/api/behavioral", () => ({
  listOutliers: (...a: unknown[]) => mockListOutliers(...a),
  getOutlier: vi.fn(),
  setIntent: (...a: unknown[]) => mockSetIntent(...a),
  feedbackBenign: (...a: unknown[]) => mockFeedbackBenign(...a),
  promoteOutlier: (...a: unknown[]) => mockPromoteOutlier(...a),
  classifyOutlier: vi.fn(),
}));

import { useBehavioralStore } from "@/stores/behavioralStore";

beforeEach(() => {
  vi.clearAllMocks();
  // Reset the store between tests.
  useBehavioralStore.setState({
    outliers: [],
    total: 0,
    page: 1,
    pageSize: 50,
    intentFilter: "all",
    isLoading: false,
    isMutating: false,
    error: null,
  });
});

describe("useBehavioralStore.fetchOutliers", () => {
  it("populates outliers and total from the API response", async () => {
    const items = [outlier({ id: "x", entity_id: "ent_x" })];
    mockListOutliers.mockResolvedValueOnce({ items, total: 1 });

    await useBehavioralStore.getState().fetchOutliers();

    const { outliers, total, isLoading, error } = useBehavioralStore.getState();
    expect(outliers).toEqual(items);
    expect(total).toBe(1);
    expect(isLoading).toBe(false);
    expect(error).toBeNull();
  });

  it("sets error state on API failure", async () => {
    mockListOutliers.mockRejectedValueOnce(new Error("network error"));

    await useBehavioralStore.getState().fetchOutliers();

    expect(useBehavioralStore.getState().error).toBeTruthy();
    expect(useBehavioralStore.getState().isLoading).toBe(false);
  });

  it("passes intent_label param when filter is not 'all'", async () => {
    mockListOutliers.mockResolvedValueOnce({ items: [], total: 0 });
    useBehavioralStore.setState({ intentFilter: "malicious" });

    await useBehavioralStore.getState().fetchOutliers();

    expect(mockListOutliers).toHaveBeenCalledWith(
      expect.objectContaining({ intent_label: "malicious" }),
    );
  });

  it("omits intent_label param when filter is 'all'", async () => {
    mockListOutliers.mockResolvedValueOnce({ items: [], total: 0 });
    useBehavioralStore.setState({ intentFilter: "all" });

    await useBehavioralStore.getState().fetchOutliers();

    expect(mockListOutliers).toHaveBeenCalledWith(
      expect.objectContaining({ intent_label: null }),
    );
  });
});

describe("useBehavioralStore.triageOutlier", () => {
  it("merges the updated outlier into the list on success", async () => {
    const original = outlier({ id: "o1", entity_id: "ent_1" });
    const updated = { ...original, intent_label: "suspicious" as const, intent_rationale: "why" };
    useBehavioralStore.setState({ outliers: [original], total: 1 });
    mockSetIntent.mockResolvedValueOnce(updated);

    await useBehavioralStore
      .getState()
      .triageOutlier("o1", { intent_label: "suspicious", rationale: "why" });

    const inStore = useBehavioralStore.getState().outliers.find((o: BehavioralOutlier) => o.id === "o1");
    expect(inStore?.intent_label).toBe("suspicious");
  });

  it("surfaces error and re-throws on API failure", async () => {
    mockSetIntent.mockRejectedValueOnce(new Error("500"));
    useBehavioralStore.setState({ outliers: [outlier({ id: "o1", entity_id: "e1" })] });

    await expect(
      useBehavioralStore
        .getState()
        .triageOutlier("o1", { intent_label: "benign", rationale: "test" }),
    ).rejects.toBeTruthy();

    expect(useBehavioralStore.getState().error).toBeTruthy();
    expect(useBehavioralStore.getState().isMutating).toBe(false);
  });
});

describe("useBehavioralStore.promote", () => {
  it("returns finding_id and re-fetches outliers on success", async () => {
    mockPromoteOutlier.mockResolvedValueOnce({ finding_id: "hfnd_xyz" });
    mockListOutliers.mockResolvedValueOnce({ items: [], total: 0 });

    const findingId = await useBehavioralStore.getState().promote("o1", { technique_ids: [] });

    expect(findingId).toBe("hfnd_xyz");
    // Re-fetch should have been called.
    expect(mockListOutliers).toHaveBeenCalledTimes(1);
  });
});
