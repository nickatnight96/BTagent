/**
 * Coverage map panel (#118 Phase C).
 *
 * `GET /validation/coverage-map` shipped with no consumer, so the question the
 * validation arc exists to answer — which detections haven't been proven to
 * work lately — couldn't be asked in the product.
 *
 * The case that matters most is the pair of empty states: "nothing is stale"
 * and "there is no coverage data at all" look identical through a server-side
 * `only_stale` filter, and one of those is good news while the other means the
 * feature has nothing to work with.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const getCoverageMap = vi.fn();

vi.mock("@/api/validation", () => ({
  getCoverageMap: (...a: unknown[]) => getCoverageMap(...a),
}));

import { CoverageMapPanel } from "@/components/validation/CoverageMapPanel";

const STALE = {
  technique_id: "T1059",
  name: "Command and Scripting Interpreter",
  last_validated: "2026-01-01T00:00:00Z",
  last_verdict: "silent_gap",
  days_since_validated: 208,
  stale: true,
  has_detection: true,
};

const NEVER = {
  technique_id: "T1078",
  name: "Valid Accounts",
  last_validated: null,
  last_verdict: null,
  days_since_validated: null,
  stale: true,
  has_detection: false,
};

const FRESH = {
  technique_id: "T1105",
  name: "Ingress Tool Transfer",
  last_validated: "2026-07-20T00:00:00Z",
  last_verdict: "validated",
  days_since_validated: 8,
  stale: false,
  has_detection: true,
};

function resp(items: unknown[], staleDays = 90) {
  return {
    items,
    total: items.length,
    stale_count: items.filter((i) => (i as { stale: boolean }).stale).length,
    stale_days: staleDays,
    only_stale: false,
  };
}

describe("CoverageMapPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCoverageMap.mockResolvedValue(resp([STALE, NEVER, FRESH]));
  });

  it("defaults to the stale-only view and counts against the full set", async () => {
    render(<CoverageMapPanel />);
    await screen.findByTestId("coverage-map-table");

    expect(screen.getByTestId("coverage-map-counts").textContent).toContain("2 of 3 stale");
    expect(screen.getByTestId("coverage-map-row-T1059")).toBeTruthy();
    expect(screen.getByTestId("coverage-map-row-T1078")).toBeTruthy();
    // Fresh techniques are the ones needing no attention — hidden by default.
    expect(screen.queryByTestId("coverage-map-row-T1105")).toBeNull();
  });

  it("shows everything when stale-only is unticked", async () => {
    render(<CoverageMapPanel />);
    await screen.findByTestId("coverage-map-table");
    fireEvent.click(screen.getByTestId("coverage-map-stale-only"));
    expect(await screen.findByTestId("coverage-map-row-T1105")).toBeTruthy();
  });

  it("distinguishes 'nothing stale' from 'no coverage data at all'", async () => {
    // These are opposite situations — one means the programme is healthy, the
    // other means it has nothing to measure — and a server-side filter would
    // return zero rows for both.
    getCoverageMap.mockResolvedValue(resp([FRESH]));
    const { unmount } = render(<CoverageMapPanel />);
    expect(await screen.findByTestId("coverage-map-none-stale")).toBeTruthy();
    expect(screen.queryByTestId("coverage-map-no-data")).toBeNull();
    unmount();

    getCoverageMap.mockResolvedValue(resp([]));
    render(<CoverageMapPanel />);
    expect(await screen.findByTestId("coverage-map-no-data")).toBeTruthy();
    expect(screen.queryByTestId("coverage-map-none-stale")).toBeNull();
  });

  it("renders a never-validated technique as such, not as 'today'", async () => {
    render(<CoverageMapPanel />);
    await screen.findByTestId("coverage-map-table");
    // A null day-count must not fall through to a zero-days reading.
    expect(screen.getByTestId("coverage-map-age-T1078").textContent).toBe("never validated");
    expect(screen.getByTestId("coverage-map-age-T1059").textContent).toBe("208d ago");
  });

  it("flags a covered-but-undetected technique separately", async () => {
    render(<CoverageMapPanel />);
    await screen.findByTestId("coverage-map-table");
    // Validated with no detection authored is a different problem from a
    // stale detection, so it must not render as an empty cell.
    expect(screen.getByTestId("coverage-map-nodetect-T1078").textContent).toBe("none");
  });

  it("refetches with a new stale window, rejecting out-of-range values", async () => {
    render(<CoverageMapPanel />);
    await screen.findByTestId("coverage-map-table");
    expect(getCoverageMap).toHaveBeenCalledWith({ staleDays: 90 });

    // 0 is below the server's ge=1 bound — sending it would 422 and read as a
    // broken panel, so the form refuses it rather than round-tripping.
    fireEvent.change(screen.getByTestId("coverage-map-stale-days"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("coverage-map-apply"));
    await waitFor(() => expect(getCoverageMap).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId("coverage-map-stale-days"), { target: { value: "30" } });
    fireEvent.click(screen.getByTestId("coverage-map-apply"));
    await waitFor(() => expect(getCoverageMap).toHaveBeenCalledWith({ staleDays: 30 }));
  });

  it("hands a technique to the caller instead of firing it", async () => {
    // The emulation trigger fires a technique, so the coverage map only
    // *loads* one into it — it must never run anything itself.
    const onValidateTechnique = vi.fn();
    render(<CoverageMapPanel onValidateTechnique={onValidateTechnique} />);
    await screen.findByTestId("coverage-map-table");

    fireEvent.click(screen.getByTestId("coverage-map-validate-T1059"));
    expect(onValidateTechnique).toHaveBeenCalledWith("T1059");
  });

  it("surfaces a load failure instead of rendering an empty map", async () => {
    getCoverageMap.mockRejectedValue(new Error("boom"));
    render(<CoverageMapPanel />);
    // An empty table here would read as "nothing is stale" — the reassuring
    // reading of a failure, which is the wrong way to fail.
    expect(await screen.findByTestId("coverage-map-error")).toBeTruthy();
    expect(screen.queryByTestId("coverage-map-none-stale")).toBeNull();
  });
});
