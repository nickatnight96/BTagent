import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { ReactElement } from "react";

const listProposals = vi.fn();
const acceptProposal = vi.fn();
const rejectProposal = vi.fn();
const validateProposal = vi.fn();
const editProposal = vi.fn();
const composeDetectionPR = vi.fn();
const recordPROutcome = vi.fn();
const proposeDetections = vi.fn();

vi.mock("@/api/detection", () => ({
  listProposals: (...a: unknown[]) => listProposals(...a),
  acceptProposal: (...a: unknown[]) => acceptProposal(...a),
  rejectProposal: (...a: unknown[]) => rejectProposal(...a),
  validateProposal: (...a: unknown[]) => validateProposal(...a),
  editProposal: (...a: unknown[]) => editProposal(...a),
  composeDetectionPR: (...a: unknown[]) => composeDetectionPR(...a),
  recordPROutcome: (...a: unknown[]) => recordPROutcome(...a),
  // The page renders ImportBundlePanel, which imports from this module.
  // A wholesale module mock has to carry every export the tree touches.
  proposeDetections: (...a: unknown[]) => proposeDetections(...a),
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
  final_sigma_yaml: null,
  technique_ids: ["T1059.001"],
  confidence: 0.9,
  rationale: "from CTI",
  state: "proposed",
  validation: null,
  validated_at: null,
  pr_url: null,
  pr_outcome: "proposed",
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

  it("edits a proposal's Sigma and refreshes", async () => {
    editProposal.mockResolvedValue({
      ...PROPOSED,
      state: "modified",
      final_sigma_yaml: "title: Encoded PowerShell (edited)\ndetection:\n  sel:\n    x: y\n  condition: sel",
    });
    renderPage(<DetectionProposalsPage />);
    const editBtn = await screen.findByTestId("proposal-edit-prop_ONE");
    await act(async () => {
      fireEvent.click(editBtn);
    });
    const textarea = await screen.findByTestId("proposal-editor-textarea-prop_ONE");
    await act(async () => {
      fireEvent.change(textarea, {
        target: { value: "title: Edited\ndetection:\n  sel:\n    x: y\n  condition: sel" },
      });
    });
    const before = listProposals.mock.calls.length;
    await act(async () => {
      fireEvent.click(screen.getByTestId("proposal-editor-save-prop_ONE"));
    });
    await waitFor(() =>
      expect(editProposal).toHaveBeenCalledWith(
        "prop_ONE",
        "title: Edited\ndetection:\n  sel:\n    x: y\n  condition: sel",
      ),
    );
    await waitFor(() =>
      expect(listProposals.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("offers no edit control for shipped rows", async () => {
    listProposals.mockResolvedValue({
      items: [
        {
          ...PROPOSED,
          id: "prop_SHIP",
          state: "accepted",
          pr_url: "https://git.example.com/detections/pull/9",
          pr_outcome: "pr_opened",
        },
      ],
      total: 1,
    });
    renderPage(<DetectionProposalsPage />);
    await screen.findByTestId("proposal-prop_SHIP");
    expect(screen.queryByTestId("proposal-edit-prop_SHIP")).toBeNull();
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

  // -------------------------------------------------------------------------
  // PR outcome (#113 Phase C)
  //
  // `POST /cti/proposals/{id}/pr-outcome` shipped with no consumer, so a rule
  // could be composed into a detection-repo PR and then nothing could ever
  // tell BTagent what happened to it. Recording a merge is what fires the
  // closed loop — the rule is installed as a hunt pack and a validation run is
  // triggered — so the whole chain sat behind an unreachable endpoint.
  // -------------------------------------------------------------------------

  const SHIPPED = {
    ...PROPOSED,
    id: "prop_PR",
    state: "accepted",
    pr_url: "https://git.example.com/detections/pull/11",
    pr_outcome: "pr_opened",
  };

  it("offers the outcome control only while the PR is open", async () => {
    // Outside pr_opened the server 409s, so showing the control would only
    // produce an error the operator can do nothing about.
    listProposals.mockResolvedValue({
      items: [
        SHIPPED,
        { ...SHIPPED, id: "prop_MERGED", pr_outcome: "merged" },
        { ...PROPOSED, id: "prop_UNSHIPPED" },
      ],
      total: 3,
    });
    renderPage(<DetectionProposalsPage />);
    await screen.findByTestId("proposal-pr-outcome-prop_PR");
    expect(screen.queryByTestId("proposal-pr-outcome-prop_MERGED")).toBeNull();
    expect(screen.queryByTestId("proposal-pr-outcome-prop_UNSHIPPED")).toBeNull();
  });

  it("records a merge and reports what the closed loop actually did", async () => {
    listProposals.mockResolvedValue({ items: [SHIPPED], total: 1 });
    recordPROutcome.mockResolvedValue({
      proposal: { ...SHIPPED, pr_outcome: "merged" },
      closed_loop: { hunt_pack: { id: "pack_1" }, validation_run: { id: "run_1" } },
    });
    renderPage(<DetectionProposalsPage />);
    const btn = await screen.findByTestId("proposal-pr-merged-btn-prop_PR");
    await act(async () => {
      fireEvent.click(btn);
    });
    await waitFor(() => expect(recordPROutcome).toHaveBeenCalledWith("prop_PR", "merged"));
    const loop = await screen.findByTestId("proposal-closed-loop-prop_PR");
    expect(loop.textContent).toContain("installed as a hunt-pack rule");
    expect(loop.textContent).toContain("validation run triggered");
  });

  it("does not claim a rule is live when the loop's hooks did not fire", async () => {
    // Both hooks are best-effort server-side. A merge with no pack and no
    // validation run must not read as a fully closed loop.
    listProposals.mockResolvedValue({ items: [SHIPPED], total: 1 });
    recordPROutcome.mockResolvedValue({
      proposal: { ...SHIPPED, pr_outcome: "merged" },
      closed_loop: {},
    });
    renderPage(<DetectionProposalsPage />);
    const btn = await screen.findByTestId("proposal-pr-merged-btn-prop_PR");
    await act(async () => {
      fireEvent.click(btn);
    });
    const loop = await screen.findByTestId("proposal-closed-loop-prop_PR");
    expect(loop.textContent).toContain("no hunt-pack entry was created");
    expect(loop.textContent).toContain("no validation run was triggered");
  });

  it("records a rejection without claiming any loop ran", async () => {
    listProposals.mockResolvedValue({ items: [SHIPPED], total: 1 });
    recordPROutcome.mockResolvedValue({
      proposal: { ...SHIPPED, pr_outcome: "rejected" },
      closed_loop: {},
    });
    renderPage(<DetectionProposalsPage />);
    const btn = await screen.findByTestId("proposal-pr-rejected-btn-prop_PR");
    await act(async () => {
      fireEvent.click(btn);
    });
    await waitFor(() => expect(recordPROutcome).toHaveBeenCalledWith("prop_PR", "rejected"));
    expect(await screen.findByTestId("proposal-pr-rejected-prop_PR")).toBeTruthy();
    expect(screen.queryByTestId("proposal-closed-loop-prop_PR")).toBeNull();
  });

  it("says the rule was not installed when recording a merge fails", async () => {
    // Ambiguity here would leave the operator unsure whether a live detection
    // is now running.
    listProposals.mockResolvedValue({ items: [SHIPPED], total: 1 });
    recordPROutcome.mockRejectedValue(new Error("409"));
    renderPage(<DetectionProposalsPage />);
    const btn = await screen.findByTestId("proposal-pr-merged-btn-prop_PR");
    await act(async () => {
      fireEvent.click(btn);
    });
    const err = await screen.findByTestId("proposals-error");
    expect(err.textContent).toContain("not installed");
    // The control stays, so the outcome can be recorded once the cause is fixed.
    expect(screen.getByTestId("proposal-pr-outcome-prop_PR")).toBeTruthy();
  });
});
