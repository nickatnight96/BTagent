import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listProposals = vi.fn();
const acceptProposal = vi.fn();
const rejectProposal = vi.fn();
const validateProposal = vi.fn();
const composeDetectionPR = vi.fn();

vi.mock("@/api/detection", () => ({
  listProposals: (...a: unknown[]) => listProposals(...a),
  acceptProposal: (...a: unknown[]) => acceptProposal(...a),
  rejectProposal: (...a: unknown[]) => rejectProposal(...a),
  validateProposal: (...a: unknown[]) => validateProposal(...a),
  composeDetectionPR: (...a: unknown[]) => composeDetectionPR(...a),
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

  it("validates a proposal and shows the telemetry verdict in place", async () => {
    validateProposal.mockResolvedValue({
      ...PROPOSED,
      validation: { verdict: "clean", total_hits: 0 },
      validated_at: "2026-07-21T13:00:00Z",
    });
    renderPage(<DetectionProposalsPage />);
    const validateBtn = await screen.findByTestId("proposal-validate-prop_ONE");
    const before = listProposals.mock.calls.length;
    await act(async () => {
      fireEvent.click(validateBtn);
    });
    await waitFor(() => expect(validateProposal).toHaveBeenCalledWith("prop_ONE"));
    expect(await screen.findByTestId("proposal-verdict-prop_ONE")).toBeTruthy();
    expect(screen.getByText(/telemetry: clean/)).toBeTruthy();
    // In-place row swap — validation must not trigger a full refetch.
    expect(listProposals.mock.calls.length).toBe(before);
  });

  it("surfaces an error when validation fails", async () => {
    validateProposal.mockRejectedValue(new Error("503"));
    renderPage(<DetectionProposalsPage />);
    const validateBtn = await screen.findByTestId("proposal-validate-prop_ONE");
    await act(async () => {
      fireEvent.click(validateBtn);
    });
    await waitFor(() => expect(screen.getByTestId("proposals-error")).toBeTruthy());
  });

  it("selects shippable accepted rows and composes a PR", async () => {
    const accepted = { ...PROPOSED, id: "prop_ACC", state: "accepted" };
    listProposals.mockResolvedValue({ items: [accepted], total: 1 });
    composeDetectionPR.mockResolvedValue({
      pr_url: "https://git.example.com/detections/pull/7",
      branch: "detections/cti-batch-1",
      commit: "abc1234",
      rule_count: 1,
      row_ids: ["prop_ACC"],
      is_mock: true,
    });
    renderPage(<DetectionProposalsPage />);
    const checkbox = await screen.findByTestId("proposal-select-prop_ACC");
    await act(async () => {
      fireEvent.click(checkbox);
    });
    const composeBtn = screen.getByTestId("compose-pr-button");
    // The shipped row now carries the PR back-link on refetch.
    listProposals.mockResolvedValue({
      items: [{ ...accepted, pr_url: "https://git.example.com/detections/pull/7" }],
      total: 1,
    });
    await act(async () => {
      fireEvent.click(composeBtn);
    });
    await waitFor(() =>
      expect(composeDetectionPR).toHaveBeenCalledWith(["prop_ACC"]),
    );
    expect(await screen.findByTestId("compose-pr-result")).toBeTruthy();
    expect(screen.getByText(/Shipped 1 rule/)).toBeTruthy();
    expect(await screen.findByTestId("proposal-pr-prop_ACC")).toBeTruthy();
  });

  it("offers no PR checkbox for proposed or already-shipped rows", async () => {
    listProposals.mockResolvedValue({
      items: [
        PROPOSED,
        {
          ...PROPOSED,
          id: "prop_SHIPPED",
          state: "accepted",
          pr_url: "https://git.example.com/detections/pull/3",
        },
      ],
      total: 2,
    });
    renderPage(<DetectionProposalsPage />);
    await screen.findByTestId("proposal-prop_SHIPPED");
    expect(screen.queryByTestId("proposal-select-prop_ONE")).toBeNull();
    expect(screen.queryByTestId("proposal-select-prop_SHIPPED")).toBeNull();
    expect(screen.getByTestId("proposal-pr-prop_SHIPPED")).toBeTruthy();
    expect(screen.queryByTestId("compose-pr-button")).toBeNull();
  });

  it("surfaces an error when composing the PR fails", async () => {
    const accepted = { ...PROPOSED, id: "prop_ACC", state: "accepted" };
    listProposals.mockResolvedValue({ items: [accepted], total: 1 });
    composeDetectionPR.mockRejectedValue(new Error("409"));
    renderPage(<DetectionProposalsPage />);
    const checkbox = await screen.findByTestId("proposal-select-prop_ACC");
    await act(async () => {
      fireEvent.click(checkbox);
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("compose-pr-button"));
    });
    await waitFor(() => expect(screen.getByTestId("proposals-error")).toBeTruthy());
  });
});
