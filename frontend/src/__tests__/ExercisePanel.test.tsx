/**
 * RTL tests for the MITRE ExercisePanel (#99 Phase C UI):
 *  1. Renders exercised techniques with outcome badges and counts.
 *  2. Stale-only toggle refetches with older_than_days=90.
 *  3. Empty states differ between no-data and no-stale.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const mockListExercises = vi.fn();

vi.mock("@/api/mitre", () => ({
  listTechniqueExercises: (...a: unknown[]) => mockListExercises(...a),
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

async function openPanel() {
  fireEvent.click(await screen.findByTestId("exercise-panel-toggle"));
}

beforeEach(() => {
  vi.clearAllMocks();
  mockListExercises.mockResolvedValue({ items: EXERCISES, total: 2 });
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

  it("stale toggle refetches with older_than_days=90", async () => {
    render(<ExercisePanel />);
    await openPanel();
    await screen.findByTestId("exercise-row-T1059.001");

    mockListExercises.mockResolvedValue({ items: [], total: 0 });
    fireEvent.click(screen.getByTestId("stale-only-toggle"));

    await waitFor(() =>
      expect(mockListExercises).toHaveBeenCalledWith({ older_than_days: 90 }),
    );
    expect(await screen.findByTestId("exercise-empty")).toHaveTextContent(
      "No stale coverage",
    );
  });

  it("shows the no-data empty state before any hunts ran", async () => {
    mockListExercises.mockResolvedValue({ items: [], total: 0 });
    render(<ExercisePanel />);
    await openPanel();

    expect(await screen.findByTestId("exercise-empty")).toHaveTextContent(
      "No hunts have exercised techniques yet",
    );
  });
});
