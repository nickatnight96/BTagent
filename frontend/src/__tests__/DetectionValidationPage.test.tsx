import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listValidationRuns = vi.fn();
const runValidation = vi.fn();

vi.mock("@/api/validation", () => ({
  listValidationRuns: (...a: unknown[]) => listValidationRuns(...a),
  runValidation: (...a: unknown[]) => runValidation(...a),
}));

import { DetectionValidationPage } from "@/components/validation/DetectionValidationPage";

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const RUN = {
  id: "dvr_ONE",
  run_id: "valrun_ONE",
  packs: ["windows_baseline"],
  scenarios_run: 2,
  total_techniques: 1,
  detected_pct: 100,
  gaps: [],
  generated_at: "2026-07-21T12:00:00Z",
  created_at: "2026-07-21T12:00:00Z",
};

describe("DetectionValidationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listValidationRuns.mockResolvedValue({ items: [RUN], total: 1 });
  });

  it("lists persisted validation runs", async () => {
    renderPage(<DetectionValidationPage />);
    expect(await screen.findByTestId("validation-run-dvr_ONE")).toBeTruthy();
    expect(screen.getByText("valrun_ONE")).toBeTruthy();
    expect(screen.getByText("100%")).toBeTruthy();
  });

  it("shows an empty state when there are no runs", async () => {
    listValidationRuns.mockResolvedValue({ items: [], total: 0 });
    renderPage(<DetectionValidationPage />);
    await waitFor(() =>
      expect(screen.getByText(/No validation runs yet/i)).toBeTruthy(),
    );
  });

  it("triggers a run and refreshes the history", async () => {
    runValidation.mockResolvedValue({ ...RUN, coverage_by_technique: [] });
    renderPage(<DetectionValidationPage />);
    const runBtn = await screen.findByTestId("validation-run");
    const before = listValidationRuns.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(runValidation).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(listValidationRuns.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("surfaces an error when the list fails", async () => {
    listValidationRuns.mockRejectedValue(new Error("boom"));
    renderPage(<DetectionValidationPage />);
    await waitFor(() => expect(screen.getByTestId("validation-error")).toBeTruthy());
  });
});
