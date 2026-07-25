import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const getHandoverSummary = vi.fn();

vi.mock("@/api/handover", () => ({
  getHandoverSummary: (...a: unknown[]) => getHandoverSummary(...a),
}));

import { HandoverCard } from "@/components/investigations/HandoverCard";

const SUMMARY = {
  window_hours: 8,
  window_start: "2026-07-24T00:00:00Z",
  generated_at: "2026-07-24T08:00:00Z",
  headline:
    "Last 8h: 2 new investigation(s), 1 updated; 5 hunt finding(s) landed (3 untriaged); 4 case(s) still open.",
  investigations: [],
  open_by_severity: { high: 2, medium: 2 },
  findings_by_severity: { critical: 1, medium: 4 },
  findings_untriaged: 3,
};

describe("HandoverCard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getHandoverSummary.mockResolvedValue(SUMMARY);
  });

  it("renders the headline and severity chips", async () => {
    render(<HandoverCard />);
    const headline = await screen.findByTestId("handover-headline");
    expect(headline.textContent).toContain("5 hunt finding(s) landed");

    // Finding chips in severity order, plus the untriaged chip.
    expect(screen.getByTestId("handover-finding-critical").textContent).toBe("1 critical");
    expect(screen.getByTestId("handover-finding-medium").textContent).toBe("4 medium");
    expect(screen.getByTestId("handover-untriaged").textContent).toBe("3 untriaged");

    // Open-backlog chips.
    expect(screen.getByTestId("handover-open-high").textContent).toBe("2 high");
    expect(screen.getByTestId("handover-open-medium").textContent).toBe("2 medium");
  });

  it("omits empty sections", async () => {
    getHandoverSummary.mockResolvedValue({
      ...SUMMARY,
      findings_by_severity: {},
      findings_untriaged: 0,
      open_by_severity: {},
    });
    render(<HandoverCard />);
    await screen.findByTestId("handover-headline");
    expect(screen.queryByTestId("handover-findings")).toBeNull();
    expect(screen.queryByTestId("handover-backlog")).toBeNull();
  });

  it("expands the full brief when the backend sent a narrative", async () => {
    getHandoverSummary.mockResolvedValue({
      ...SUMMARY,
      narrative: "Shift brief — last 8h:\nNew cases (1):\n  - [high] X (pending)",
    });
    render(<HandoverCard />);
    await screen.findByTestId("handover-headline");

    expect(screen.queryByTestId("handover-brief")).toBeNull();
    fireEvent.click(screen.getByTestId("handover-brief-toggle"));
    const brief = screen.getByTestId("handover-brief");
    expect(brief.textContent).toContain("New cases (1):");
  });

  it("omits the brief toggle when the payload has no narrative", async () => {
    render(<HandoverCard />);
    await screen.findByTestId("handover-headline");
    expect(screen.queryByTestId("handover-brief-toggle")).toBeNull();
  });

  it("renders nothing when the fetch fails", async () => {
    getHandoverSummary.mockRejectedValue(new Error("boom"));
    render(<HandoverCard />);
    await waitFor(() => expect(getHandoverSummary).toHaveBeenCalled());
    expect(screen.queryByTestId("handover-card")).toBeNull();
  });
});
