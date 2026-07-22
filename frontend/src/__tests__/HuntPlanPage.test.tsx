/**
 * RTL tests for the HuntPlanPage (#99 Phase A UI):
 *  1. Generate is disabled until an adversary or TTP is entered.
 *  2. Generating renders exec summary, hypotheses, and runbook entries.
 *  3. Comma/space input is tokenized into the request payload.
 *  4. API failure surfaces in the error alert.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const mockGeneratePlan = vi.fn();

vi.mock("@/api/hunts", () => ({
  generateHuntPlan: (...a: unknown[]) => mockGeneratePlan(...a),
}));

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { HuntPlanPage } from "@/components/hunts/HuntPlanPage";

const PLAN = {
  id: "hunt_01TEST",
  org_id: "org_default",
  state: "ready",
  input: { adversaries: ["APT29"], ttps: [] },
  executive_summary: {
    adversary_profile: "APT29 — SVR-attributed espionage group.",
    scope_description: "",
    success_criteria: "Any confirmed hit escalates to IR.",
    estimated_effort_hours: 6,
    coverage_delta: {},
  },
  hypotheses: [
    {
      id: "h_001",
      ttp_id: "T1059.001",
      ttp_name: "PowerShell",
      rationale: "APT29 uses encoded PowerShell.",
      behavioral_description: "powershell.exe with -EncodedCommand",
      priority: 0.85,
      sources: ["adversary:APT29"],
    },
  ],
  ttp_entries: [
    {
      ttp_id: "T1059.001",
      ttp_name: "PowerShell",
      rationale: "APT29 uses encoded PowerShell.",
      behavioral_description: "powershell.exe with -EncodedCommand",
      queries: {
        splunk: {
          backend: "splunk",
          query: "index=endpoint EventCode=4688 powershell",
          notes: "",
        },
      },
      expected_noise: {
        expected_hits_per_day: 120,
        sample_window_days: 30,
        computed_at: null,
      },
      pivot_questions: ["Is the parent an office app?"],
      evidence_checklist: ["Full process tree"],
      owner_id: null,
      state: "not_started",
    },
  ],
  created_at: "2026-07-22T21:00:00Z",
};

function renderPage() {
  return render(
    <MemoryRouter>
      <HuntPlanPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGeneratePlan.mockResolvedValue(PLAN);
});

describe("HuntPlanPage", () => {
  it("disables Generate until a target is entered", () => {
    renderPage();
    const btn = screen.getByTestId("generate-plan");
    expect(btn).toBeDisabled();

    fireEvent.change(screen.getByTestId("plan-adversaries-input"), {
      target: { value: "APT29" },
    });
    expect(btn).not.toBeDisabled();
  });

  it("renders exec summary, hypotheses, and runbook entries after generate", async () => {
    renderPage();
    fireEvent.change(screen.getByTestId("plan-adversaries-input"), {
      target: { value: "APT29" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    expect(await screen.findByTestId("hunt-plan-result")).toBeInTheDocument();
    expect(
      screen.getByText("APT29 — SVR-attributed espionage group."),
    ).toBeInTheDocument();
    expect(screen.getByTestId("hypothesis-h_001")).toBeInTheDocument();
    expect(screen.getByText("0.85")).toBeInTheDocument();
    const entry = screen.getByTestId("runbook-T1059.001");
    expect(entry).toHaveTextContent("index=endpoint EventCode=4688 powershell");
    expect(entry).toHaveTextContent("~120 hits/day");
    expect(entry).toHaveTextContent("Is the parent an office app?");
    expect(entry).toHaveTextContent("Full process tree");
    expect(screen.getByText(/1 hypotheses · 1 runbook entries/)).toBeInTheDocument();
  });

  it("tokenizes comma/space separated inputs into the request", async () => {
    renderPage();
    fireEvent.change(screen.getByTestId("plan-adversaries-input"), {
      target: { value: "APT29, FIN7" },
    });
    fireEvent.change(screen.getByTestId("plan-ttps-input"), {
      target: { value: "T1059.001 T1078.004" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    await waitFor(() =>
      expect(mockGeneratePlan).toHaveBeenCalledWith({
        adversaries: ["APT29", "FIN7"],
        ttps: ["T1059.001", "T1078.004"],
      }),
    );
  });

  it("surfaces API failure in the alert", async () => {
    mockGeneratePlan.mockRejectedValue(new Error("planning backend down"));
    renderPage();
    fireEvent.change(screen.getByTestId("plan-ttps-input"), {
      target: { value: "T1059.001" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "planning backend down",
    );
    expect(screen.queryByTestId("hunt-plan-result")).not.toBeInTheDocument();
  });
});
