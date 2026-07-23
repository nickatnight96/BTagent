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
const mockListPlans = vi.fn();
const mockGetPlan = vi.fn();

vi.mock("@/api/hunts", () => ({
  generateHuntPlan: (...a: unknown[]) => mockGeneratePlan(...a),
  listHuntPlans: (...a: unknown[]) => mockListPlans(...a),
  getHuntPlan: (...a: unknown[]) => mockGetPlan(...a),
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

const SUMMARY_DIRECT = {
  id: "hunt_01TEST",
  status: "ready",
  adversaries: ["APT29"],
  ttps: [],
  hypothesis_count: 1,
  entry_count: 1,
  from_proposal: false,
  created_at: "2026-07-22T21:00:00Z",
};

const SUMMARY_PROPOSAL = {
  id: "hplan_02PROP",
  status: "ready",
  adversaries: [],
  ttps: ["T1078.004", "T1110", "T1556", "T1621", "T1098"],
  hypothesis_count: 5,
  entry_count: 5,
  from_proposal: true,
  created_at: "2026-07-21T10:00:00Z",
};

function renderPage() {
  return render(
    <MemoryRouter>
      <HuntPlanPage />
    </MemoryRouter>,
  );
}

async function openHistory() {
  const toggle = await screen.findByTestId("plan-history-toggle");
  fireEvent.click(toggle);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGeneratePlan.mockResolvedValue(PLAN);
  mockListPlans.mockResolvedValue({
    items: [SUMMARY_DIRECT, SUMMARY_PROPOSAL],
    total: 2,
  });
  mockGetPlan.mockResolvedValue(PLAN);
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

describe("HuntPlanPage plan history", () => {
  it("renders stored summaries with labels, counts, and proposal badge", async () => {
    renderPage();
    await openHistory();

    expect(screen.getByText("APT29")).toBeInTheDocument();
    // 5 ttps → first 4 + overflow marker
    expect(
      screen.getByText("T1078.004, T1110, T1556, T1621 +1"),
    ).toBeInTheDocument();
    expect(screen.getByText(/1 hypotheses · 1 entries/)).toBeInTheDocument();
    expect(screen.getByTestId("proposal-badge-hplan_02PROP")).toBeInTheDocument();
    expect(
      screen.queryByTestId("proposal-badge-hunt_01TEST"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("(2)")).toBeInTheDocument();
    expect(mockListPlans).toHaveBeenCalledWith({ page_size: 20 });
  });

  it("re-opens a stored plan on click via the detail endpoint", async () => {
    renderPage();
    await openHistory();

    fireEvent.click(screen.getByTestId("plan-history-item-hunt_01TEST"));

    await waitFor(() => expect(mockGetPlan).toHaveBeenCalledWith("hunt_01TEST"));
    expect(await screen.findByTestId("hunt-plan-result")).toBeInTheDocument();
    expect(screen.getByTestId("runbook-T1059.001")).toBeInTheDocument();
    expect(screen.getByText("(open)")).toBeInTheDocument();
  });

  it("refreshes history after generating a new plan", async () => {
    renderPage();
    await waitFor(() => expect(mockListPlans).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId("plan-adversaries-input"), {
      target: { value: "APT29" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    await waitFor(() => expect(mockGeneratePlan).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockListPlans).toHaveBeenCalledTimes(2));
  });

  it("renders no history panel when the store is empty", async () => {
    mockListPlans.mockResolvedValue({ items: [], total: 0 });
    renderPage();

    await waitFor(() => expect(mockListPlans).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId("plan-history")).not.toBeInTheDocument();
  });
});
