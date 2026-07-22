import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";

const getNoiseBaseline = vi.fn();
const createSuppression = vi.fn();

vi.mock("@/api/hunt", () => ({
  getNoiseBaseline: (...a: unknown[]) => getNoiseBaseline(...a),
  createSuppression: (...a: unknown[]) => createSuppression(...a),
}));

import { NoisyRulesPanel } from "@/components/hunt/NoisyRulesPanel";

const NOISY = {
  items: [
    {
      pack_id: "pack_win",
      pack_name: "Windows Baseline",
      rule_id: "r1",
      rule_title: "Encoded PowerShell",
      runs_observed: 12,
      runs_hit: 12,
      hit_rate: 1.0,
      total_hits: 84,
      avg_hits_per_run: 7.0,
      last_hit_at: "2026-07-22T08:00:00Z",
    },
    {
      pack_id: "pack_win",
      pack_name: "Windows Baseline",
      rule_id: "r2",
      rule_title: "Service Install",
      runs_observed: 10,
      runs_hit: 8,
      hit_rate: 0.8,
      total_hits: 9,
      avg_hits_per_run: 0.9,
      last_hit_at: "2026-07-21T08:00:00Z",
    },
  ],
  runs_analyzed: 12,
  min_runs: 3,
  hit_rate_threshold: 0.8,
};

describe("NoisyRulesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders nothing when the baseline is quiet", async () => {
    getNoiseBaseline.mockResolvedValue({ ...NOISY, items: [] });
    render(<NoisyRulesPanel />);
    await waitFor(() => expect(getNoiseBaseline).toHaveBeenCalled());
    expect(screen.queryByTestId("noisy-rules-panel")).toBeNull();
  });

  it("renders nothing when the request fails", async () => {
    getNoiseBaseline.mockRejectedValue(new Error("boom"));
    render(<NoisyRulesPanel />);
    await waitFor(() => expect(getNoiseBaseline).toHaveBeenCalled());
    expect(screen.queryByTestId("noisy-rules-panel")).toBeNull();
  });

  it("lists noisy rules with hit-rate stats when expanded", async () => {
    getNoiseBaseline.mockResolvedValue(NOISY);
    render(<NoisyRulesPanel />);
    const toggle = await screen.findByTestId("noisy-rules-toggle");
    expect(toggle).toHaveTextContent("Noisy rules (2)");
    await act(async () => {
      fireEvent.click(toggle);
    });
    expect(screen.getByTestId("noisy-rule-r1")).toHaveTextContent("Encoded PowerShell");
    expect(screen.getByTestId("noisy-rule-rate-r1")).toHaveTextContent("hit 100% of 12 runs");
    expect(screen.getByTestId("noisy-rule-r2")).toHaveTextContent("Service Install");
    expect(screen.getByTestId("noisy-rule-rate-r2")).toHaveTextContent("hit 80% of 10 runs");
    expect(screen.getByText(/nothing is suppressed automatically/i)).toBeTruthy();
  });

  it("one-click suppress creates a rule_ids-targeted suppression", async () => {
    getNoiseBaseline.mockResolvedValue(NOISY);
    createSuppression.mockResolvedValue({ id: "sup_1" });
    render(<NoisyRulesPanel canSuppress />);
    const toggle = await screen.findByTestId("noisy-rules-toggle");
    await act(async () => {
      fireEvent.click(toggle);
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("noisy-rule-suppress-r1"));
    });
    await waitFor(() => expect(createSuppression).toHaveBeenCalledTimes(1));
    const body = createSuppression.mock.calls[0]?.[0] as {
      name: string;
      reason: string;
      match: { rule_ids: string[] };
    };
    expect(body.match.rule_ids).toEqual(["r1"]);
    expect(body.name).toContain("Encoded PowerShell");
    expect(body.reason).toContain("hit 100% of 12 runs");
    // The row flips to a suppressed badge; the button is gone.
    expect(await screen.findByTestId("noisy-rule-muted-r1")).toBeTruthy();
    expect(screen.queryByTestId("noisy-rule-suppress-r1")).toBeNull();
    // Sibling rule keeps its button.
    expect(screen.getByTestId("noisy-rule-suppress-r2")).toBeTruthy();
  });

  it("suppress failure surfaces an inline error and keeps the button", async () => {
    getNoiseBaseline.mockResolvedValue(NOISY);
    createSuppression.mockRejectedValue(new Error("409"));
    render(<NoisyRulesPanel canSuppress />);
    const toggle = await screen.findByTestId("noisy-rules-toggle");
    await act(async () => {
      fireEvent.click(toggle);
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("noisy-rule-suppress-r1"));
    });
    await waitFor(() => expect(screen.getByTestId("noisy-rules-error")).toBeTruthy());
    expect(screen.getByTestId("noisy-rule-suppress-r1")).toBeTruthy();
  });

  it("hides suppress buttons without canSuppress", async () => {
    getNoiseBaseline.mockResolvedValue(NOISY);
    render(<NoisyRulesPanel />);
    const toggle = await screen.findByTestId("noisy-rules-toggle");
    await act(async () => {
      fireEvent.click(toggle);
    });
    expect(screen.queryByTestId("noisy-rule-suppress-r1")).toBeNull();
    expect(screen.getByText(/requires senior_analyst/i)).toBeTruthy();
  });

  it("refresh re-runs the analysis", async () => {
    getNoiseBaseline.mockResolvedValue(NOISY);
    render(<NoisyRulesPanel />);
    await screen.findByTestId("noisy-rules-panel");
    const before = getNoiseBaseline.mock.calls.length;
    await act(async () => {
      fireEvent.click(screen.getByTestId("noisy-rules-refresh"));
    });
    await waitFor(() =>
      expect(getNoiseBaseline.mock.calls.length).toBeGreaterThan(before),
    );
  });
});
