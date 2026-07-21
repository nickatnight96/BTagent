import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listProposals = vi.fn();
const acceptProposal = vi.fn();
const rejectProposal = vi.fn();

vi.mock("@/api/detection", () => ({
  listProposals: (...a: unknown[]) => listProposals(...a),
  acceptProposal: (...a: unknown[]) => acceptProposal(...a),
  rejectProposal: (...a: unknown[]) => rejectProposal(...a),
}));

import { DetectionProposalsPage } from "@/components/detection/DetectionProposalsPage";

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const PROPOSED = {
  id: "prop_ONE",
  org_id: "org_1",
  proposal_id: "dp_ONE",
  source_stix_id: "indicator--1",
  bundle_id: null,
  title: "Encoded PowerShell",
  sigma_yaml: "title: Encoded PowerShell\ndetection:\n  sel:\n    CommandLine|contains: -enc",
  technique_ids: ["T1059.001"],
  confidence: 0.9,
  rationale: "from CTI",
  state: "proposed",
  validation: null,
  validated_at: null,
  pr_url: null,
  review_rationale: "",
  reviewed_by: null,
  reviewed_at: null,
  created_at: "2026-07-21T12:00:00Z",
  updated_at: "2026-07-21T12:00:00Z",
};

describe("DetectionProposalsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listProposals.mockResolvedValue({ items: [PROPOSED], total: 1 });
  });

  it("lists proposals with technique + confidence", async () => {
    renderPage(<DetectionProposalsPage />);
    expect(await screen.findByTestId("proposal-prop_ONE")).toBeTruthy();
    expect(screen.getByText("Encoded PowerShell")).toBeTruthy();
    expect(screen.getByText(/T1059\.001.*90%/)).toBeTruthy();
  });

  it("expands to show the Sigma rule", async () => {
    renderPage(<DetectionProposalsPage />);
    const toggle = await screen.findByTestId("proposal-toggle-prop_ONE");
    await act(async () => {
      fireEvent.click(toggle);
    });
    expect(screen.getByTestId("proposal-sigma-prop_ONE")).toBeTruthy();
  });

  it("accepts a proposal and refreshes", async () => {
    acceptProposal.mockResolvedValue({ ...PROPOSED, state: "accepted" });
    renderPage(<DetectionProposalsPage />);
    const acceptBtn = await screen.findByTestId("proposal-accept-prop_ONE");
    const before = listProposals.mock.calls.length;
    await act(async () => {
      fireEvent.click(acceptBtn);
    });
    await waitFor(() => expect(acceptProposal).toHaveBeenCalledWith("prop_ONE"));
    await waitFor(() =>
      expect(listProposals.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("hides accept/reject for non-proposed states", async () => {
    listProposals.mockResolvedValue({
      items: [{ ...PROPOSED, id: "prop_TWO", state: "accepted" }],
      total: 1,
    });
    renderPage(<DetectionProposalsPage />);
    await screen.findByTestId("proposal-prop_TWO");
    expect(screen.queryByTestId("proposal-accept-prop_TWO")).toBeNull();
  });

  it("surfaces an error when the list fails", async () => {
    listProposals.mockRejectedValue(new Error("boom"));
    renderPage(<DetectionProposalsPage />);
    await waitFor(() => expect(screen.getByTestId("proposals-error")).toBeTruthy());
  });
});
