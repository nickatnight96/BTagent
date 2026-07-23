/**
 * RTL tests for the MITRE ExercisePanel (#99 Phase C UI):
 *  1. Renders exercised techniques with outcome badges and counts.
 *  2. Stale mode refetches with older_than_days=90.
 *  3. Never-exercised mode fetches the gaps route and renders gap rows.
 *  4. Empty states differ per mode.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const mockListExercises = vi.fn();
const mockListGaps = vi.fn();

vi.mock("@/api/mitre", () => ({
  listTechniqueExercises: (...a: unknown[]) => mockListExercises(...a),
  listExerciseGaps: (...a: unknown[]) => mockListGaps(...a),
}));

import { ExercisePanel } from "@/components/mitre/ExercisePanel";

const EXERCISES = [
  {
    technique_id: "T1059.001",
    last_exercised_at: "2026-07-22T10:00:00Z",
    last_plan_id: "hunt_01",
    last_run_id: "hrun_01",
    last_outcome: "hit",
    exercise_count: 3,
  },
  {
    technique_id: "T1105",
    last_exercised_at: "2026-07-20T10:00:00Z",
    last_plan_id: "hunt_02",
    last_run_id: "hrun_02",
    last_outcome: "clean",
    exercise_count: 1,
  },
];

const GAPS = [
  { technique_id: "T1547", name: "Boot or Logon Autostart", tactic: "persistence" },
  { technique_id: "T1620", name: "Reflective Code Loading", tactic: "defense-evasion" },
];

async function openPanel() {
  fireEvent.click(await screen.findByTestId("exercise-panel-toggle"));
}

beforeEach(() => {
  vi.clearAllMocks();
  mockListExercises.mockResolvedValue({ items: EXERCISES, total: 2 });
  mockListGaps.mockResolvedValue({ items: GAPS, total: 2 });
});

describe("ExercisePanel", () => {
  it("renders exercised techniques with outcomes and counts", async () => {
    render(<ExercisePanel />);
    await openPanel();

    const hitRow = await screen.findByTestId("exercise-row-T1059.001");
    expect(hitRow).toHaveTextContent("T1059.001");
    expect(hitRow).toHaveTextContent("×3");
    expect(hitRow).toHaveTextContent("hit");
    const cleanRow = screen.getByTestId("exercise-row-T1105");
    expect(cleanRow).toHaveTextContent("clean");
    expect(screen.getByText("(2)")).toBeInTheDocument();
    expect(mockListExercises).toHaveBeenCalledWith(undefined);
  });

  it("stale mode refetches with older_than_days=90", async () => {
    render(<ExercisePanel />);
    await openPanel();
    await screen.findByTestId("exercise-row-T1059.001");

    mockListExercises.mockResolvedValue({ items: [], total: 0 });
    fireEvent.click(screen.getByTestId("exercise-mode-stale"));

    await waitFor(() =>
      expect(mockListExercises).toHaveBeenCalledWith({ older_than_days: 90 }),
    );
    expect(await screen.findByTestId("exercise-empty")).toHaveTextContent(
      "No stale coverage",
    );
  });

  it("never-exercised mode fetches gaps and renders gap rows", async () => {
    render(<ExercisePanel />);
    await openPanel();
    await screen.findByTestId("exercise-row-T1059.001");

    fireEvent.click(screen.getByTestId("exercise-mode-never"));

    await waitFor(() =>
      expect(mockListGaps).toHaveBeenCalledWith({ page_size: 25 }),
    );
    const gapRow = await screen.findByTestId("gap-row-T1547");
    expect(gapRow).toHaveTextContent("T1547");
    expect(gapRow).toHaveTextContent("Boot or Logon Autostart");
    expect(gapRow).toHaveTextContent("persistence");
    expect(screen.getByTestId("gap-row-T1620")).toBeInTheDocument();
    expect(screen.queryByTestId("exercise-row-T1059.001")).not.toBeInTheDocument();
  });

  it("shows mode-specific empty states", async () => {
    mockListExercises.mockResolvedValue({ items: [], total: 0 });
    mockListGaps.mockResolvedValue({ items: [], total: 0 });
    render(<ExercisePanel />);
    await openPanel();

    expect(await screen.findByTestId("exercise-empty")).toHaveTextContent(
      "No hunts have exercised techniques yet",
    );

    fireEvent.click(screen.getByTestId("exercise-mode-never"));
    await waitFor(() =>
      expect(screen.getByTestId("exercise-empty")).toHaveTextContent("No gaps"),
    );
  });
});
