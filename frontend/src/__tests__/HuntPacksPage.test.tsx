/**
 * RTL tests for the HuntPacks page's rule grid (#577 follow-through).
 *
 * Covers the two user-visible claims this page makes about coverage, both of
 * which were wrong before:
 *
 *  1. Rules the sweep cap has never executed appear in the grid. They have no
 *     `rule_stats` entry, so they were absent from the union the rule list is
 *     built from and could not be rendered at all — a pack whose tail is
 *     permanently capped looked complete and quiet.
 *  2. The rule count reports the pack's real size, not the number of rules we
 *     happen to have history for. `rules.length || rule_count` preferred the
 *     observed count, which under-reported coverage in the one place an
 *     analyst would look to notice it.
 *
 * The store is left real and only the three API reads behind `fetchAll` are
 * mocked, so the derivation under test is the one that ships.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { HuntPackRun, NoiseBaseline } from "@/types/hunt";

const mockListPackRuns = vi.fn();
const mockGetNoiseBaseline = vi.fn();
const mockListHuntPacks = vi.fn();

// Spread-real + override: a wholesale factory turns every unnamed export into
// `undefined`, which has repeatedly crashed page tests when the page grew a
// new import (see HuntPackagePage.test.tsx).
vi.mock("@/api/hunt", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/hunt")>()),
  listPackRuns: (...a: unknown[]) => mockListPackRuns(...a),
  getNoiseBaseline: (...a: unknown[]) => mockGetNoiseBaseline(...a),
  listHuntPacks: (...a: unknown[]) => mockListHuntPacks(...a),
}));

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { HuntPacksPage } from "@/components/hunts/HuntPacksPage";
import { useHuntPacksStore } from "@/stores/huntPacksStore";

const PACK_ID = "hpack_win";

function packRun(rule_stats: HuntPackRun["rule_stats"]): HuntPackRun {
  return {
    org_id: "org_default",
    run_id: "hrun_1",
    pack_id: PACK_ID,
    pack_name: "Windows Baseline",
    pack_version: "1.0.0",
    backends: ["splunk"],
    rule_stats,
    hit_count: 0,
    error_count: 0,
    findings_created: 0,
    status: "completed",
    error: null,
    truncated: true,
    rules_not_run: ["rule_dark"],
    started_at: "2026-07-27T10:00:00Z",
    completed_at: "2026-07-27T10:00:05Z",
  } as HuntPackRun;
}

const BASELINE: NoiseBaseline = {
  items: [],
  runs_analyzed: 4,
  min_runs: 3,
  hit_rate_threshold: 0.8,
  never_run: [
    {
      pack_id: PACK_ID,
      pack_name: "Windows Baseline",
      rule_id: "rule_dark",
      runs_skipped: 14,
      first_skipped_at: "2026-06-01T08:00:00Z",
      last_skipped_at: "2026-07-27T08:00:00Z",
      days_dark: 56,
      window_days: 60,
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <HuntPacksPage />
    </MemoryRouter>,
  );
}

describe("HuntPacksPage rule grid", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useHuntPacksStore.setState({
      runs: [],
      baseline: null,
      catalog: [],
      selectedPackId: null,
      selectedRuleId: null,
      togglingPackId: null,
      isLoading: false,
      error: null,
    });
    mockListPackRuns.mockResolvedValue({
      items: [packRun({ rule1: { title: "Encoded PowerShell", hits: 2, errors: 0 } })],
      total: 1,
    });
    mockGetNoiseBaseline.mockResolvedValue(BASELINE);
    mockListHuntPacks.mockResolvedValue({
      items: [
        {
          pack_id: "windows_baseline",
          manifest_pack_id: PACK_ID,
          name: "Windows Baseline",
          version: "1.0.0",
          description: "",
          // The pack really has 40 rules; history only covers one.
          rule_count: 40,
          source: "builtin",
          enabled: true,
          installed: true,
          default_enabled: true,
          installed_at: null,
          updated_at: null,
          updated_by: null,
        },
      ],
    });
  });

  it("renders a chip for a rule no sweep ever executed", async () => {
    renderPage();
    const chip = await screen.findByTestId("rule-chip-rule_dark");
    expect(chip.getAttribute("title")).toContain("Never run");
    // The observed rule is still there — this adds to the grid, not replaces.
    expect(screen.getByTestId("rule-chip-rule1")).toBeTruthy();
  });

  it("reports the pack's real rule count, not the number observed", async () => {
    renderPage();
    const count = await screen.findByTestId(`pack-rule-count-${PACK_ID}`);
    // 40 from the catalog. Before the fix this read "2" (the derived list:
    // one observed rule plus the never-run one).
    await waitFor(() => expect(count.textContent).toBe("40"));
  });

  it("falls back to the derived count for an ad-hoc pack with no catalog entry", async () => {
    // A pack with run history but no catalog row has no authoritative count,
    // so the derived list is the best available answer and must not render 0.
    mockListHuntPacks.mockResolvedValue({ items: [] });
    renderPage();
    const count = await screen.findByTestId(`pack-rule-count-${PACK_ID}`);
    await waitFor(() => expect(count.textContent).toBe("2"));
  });

  it("a never-run rule's detail explains the schedule, not a hit rate", async () => {
    renderPage();
    const chip = await screen.findByTestId("rule-chip-rule_dark");
    chip.click();
    const detail = await screen.findByTestId("rule-detail-never-run");
    expect(detail.textContent).toContain("14");
    expect(detail.textContent).toContain("Never executed");
    // A 0% hit rate would read as a measurement of a rule that never ran.
    expect(detail.textContent).not.toContain("hit rate");
  });
});
