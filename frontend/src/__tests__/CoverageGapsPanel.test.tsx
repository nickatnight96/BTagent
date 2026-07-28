/**
 * Detection gaps + environment-relevant TTPs (MITRE).
 *
 * `GET /mitre/gaps` and `GET /mitre/search-ttps` both shipped without a
 * consumer. Wiring them up surfaced two latent defects in the client that had
 * never been observed *because* nothing called it: the path was
 * `/v1/mitre/detection-gaps`, which the backend has never served, and the
 * `DetectionGap` type described a per-technique shape with `severity` and
 * `recommendation` that the API has never returned.
 *
 * The load-bearing case here is the partial one: the two fetches are
 * independent, and losing the softer suggestion must not take the harder gap
 * list down with it.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const getDetectionGaps = vi.fn();
const suggestTTPsForEnvironment = vi.fn();

vi.mock("@/api/mitre", () => ({
  getDetectionGaps: (...a: unknown[]) => getDetectionGaps(...a),
  suggestTTPsForEnvironment: (...a: unknown[]) => suggestTTPsForEnvironment(...a),
}));

import { CoverageGapsPanel } from "@/components/mitre/CoverageGapsPanel";

const GAPS = [
  {
    tactic: "initial-access",
    techniques_without_detection: ["T1566", "T1190"],
    data_sources_missing: ["Email Gateway", "Web Proxy"],
  },
  {
    tactic: "persistence",
    techniques_without_detection: ["T1053"],
    data_sources_missing: [],
  },
];

const TTPS = [
  { id: "T1059.001", name: "PowerShell", tactic: "execution", description: "" },
];

describe("CoverageGapsPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getDetectionGaps.mockResolvedValue(GAPS);
    suggestTTPsForEnvironment.mockResolvedValue(TTPS);
  });

  it("totals uncovered techniques across tactics", async () => {
    render(<CoverageGapsPanel />);
    const panel = await screen.findByTestId("coverage-gaps-panel");
    // 2 + 1 across 2 tactics — the roll-up is the headline number.
    expect(panel.textContent).toContain("3 techniques with no detection across 2 tactics");
  });

  it("names the technique ids and the data sources that would close the gap", async () => {
    render(<CoverageGapsPanel />);
    const row = await screen.findByTestId("coverage-gap-initial-access");
    expect(row.textContent).toContain("T1566");
    // The missing sources are the actionable half — what to onboard.
    expect(screen.getByTestId("coverage-gap-sources-initial-access").textContent).toContain(
      "Email Gateway",
    );
  });

  it("omits the data-source line for a tactic with none missing", async () => {
    render(<CoverageGapsPanel />);
    await screen.findByTestId("coverage-gap-persistence");
    expect(screen.queryByTestId("coverage-gap-sources-persistence")).toBeNull();
  });

  it("keeps the gap list when the TTP suggestion fails", async () => {
    // The suggestion is the softer of the two. Losing it must not take the
    // harder finding down with it.
    suggestTTPsForEnvironment.mockRejectedValue(new Error("boom"));
    render(<CoverageGapsPanel />);
    expect(await screen.findByTestId("coverage-gaps-list")).toBeTruthy();
    expect(screen.queryByTestId("env-ttps")).toBeNull();
  });

  it("keeps the TTP suggestion when the gap fetch fails", async () => {
    getDetectionGaps.mockRejectedValue(new Error("boom"));
    render(<CoverageGapsPanel />);
    expect(await screen.findByTestId("env-ttps-list")).toBeTruthy();
    expect(screen.queryByTestId("coverage-gaps-list")).toBeNull();
  });

  it("only errors when both fetches fail", async () => {
    getDetectionGaps.mockRejectedValue(new Error("boom"));
    suggestTTPsForEnvironment.mockRejectedValue(new Error("boom"));
    render(<CoverageGapsPanel />);
    expect(await screen.findByTestId("coverage-gaps-error")).toBeTruthy();
  });

  it("says a clean gap list means every tactic has detection data", async () => {
    getDetectionGaps.mockResolvedValue([]);
    render(<CoverageGapsPanel />);
    expect((await screen.findByTestId("coverage-gaps-none")).textContent).toContain(
      "Every tactic has detection data",
    );
  });

  it("blames the empty profile rather than implying nothing is relevant", async () => {
    // No suggestions almost always means an unfilled org profile, not that
    // the stack faces no techniques.
    suggestTTPsForEnvironment.mockResolvedValue([]);
    render(<CoverageGapsPanel />);
    expect((await screen.findByTestId("env-ttps-empty")).textContent).toContain(
      "no tech stack recorded",
    );
  });

  it("renders each suggested technique with its id and name", async () => {
    render(<CoverageGapsPanel />);
    const ttp = await screen.findByTestId("env-ttp-T1059.001");
    expect(ttp.textContent).toContain("T1059.001");
    expect(ttp.textContent).toContain("PowerShell");
  });

  it("asks the environment endpoint for nothing — the server derives it", async () => {
    render(<CoverageGapsPanel />);
    await waitFor(() => expect(suggestTTPsForEnvironment).toHaveBeenCalled());
    // No query argument: this is not the free-text technique search.
    expect(suggestTTPsForEnvironment).toHaveBeenCalledWith();
  });
});
