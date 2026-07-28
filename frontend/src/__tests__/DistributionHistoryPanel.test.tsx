/**
 * Distribution ledger on the Reports page (EPIC-6 / #473 ratchet).
 *
 * `GET /reports/distributions` — who received which report, at what TLP
 * marking, and who approved the release — had no consumer. For an audit
 * surface, curl-only is close to nonexistent: the IC asking "did the
 * advisory actually reach the ISAC?" mid-incident is exactly the person who
 * won't reach for curl.
 *
 * The cases that carry weight: an empty ledger is a meaningful statement
 * and renders explicitly, and a distribution with no recorded approver is
 * flagged rather than blending in — that row is what an auditor is scanning
 * this list for.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const listReportDistributions = vi.fn();

vi.mock("@/api/reports", () => ({
  listReportDistributions: (...a: unknown[]) => listReportDistributions(...a),
}));

import { DistributionHistoryPanel } from "@/components/reports/DistributionHistoryPanel";
import type { ReportDistribution } from "@/types/reports";

function makeRow(over: Partial<ReportDistribution> = {}): ReportDistribution {
  return {
    id: `dist_${Math.random().toString(36).slice(2, 8)}`,
    report_id: "rpt_1",
    audience: "isac",
    recipient: "FS-ISAC",
    sent_at: "2026-07-28T12:00:00Z",
    tlp_applied: "amber",
    approver_id: "usr_ic",
    ...over,
  };
}

function respond(rows: ReportDistribution[]) {
  listReportDistributions.mockResolvedValue({
    distributions: rows,
    count: rows.length,
    status: "success",
  });
}

describe("DistributionHistoryPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    respond([makeRow()]);
  });

  it("hides itself entirely when the fetch fails", async () => {
    // Same self-effacing convention as every panel: the GET is report:view
    // (analyst+), so a 403 means nothing on this page works anyway.
    listReportDistributions.mockRejectedValue(new Error("forbidden"));
    const { container } = render(<DistributionHistoryPanel />);
    await waitFor(() => expect(listReportDistributions).toHaveBeenCalled());
    expect(screen.queryByTestId("reports-distributions-panel")).toBeNull();
    expect(container.textContent).toBe("");
  });

  it("states an empty ledger explicitly — it is an audit answer, not a blank", async () => {
    respond([]);
    render(<DistributionHistoryPanel />);
    expect(
      (await screen.findByTestId("reports-distributions-empty")).textContent,
    ).toContain("No reports have been distributed");
  });

  it("shows recipient, audience, TLP marking and report id per row", async () => {
    respond([makeRow({ id: "dist_a", recipient: "CISA", audience: "agency" })]);
    render(<DistributionHistoryPanel />);

    const row = await screen.findByTestId("reports-distribution-dist_a");
    expect(row.textContent).toContain("CISA");
    expect(row.textContent).toContain("agency");
    expect(row.textContent).toContain("rpt_1");
    expect(screen.getByTestId("reports-distribution-tlp-dist_a").textContent).toBe("TLP:amber");
  });

  it("names the approver when one is recorded", async () => {
    respond([makeRow({ id: "dist_ok", approver_id: "usr_commander" })]);
    render(<DistributionHistoryPanel />);
    const row = await screen.findByTestId("reports-distribution-dist_ok");
    expect(row.textContent).toContain("approved by usr_commander");
    expect(screen.queryByTestId("reports-distribution-unapproved-dist_ok")).toBeNull();
  });

  it("flags a release with no recorded approver instead of blending it in", async () => {
    // The accountability gap is the row an auditor is scanning for.
    respond([makeRow({ id: "dist_gap", approver_id: null })]);
    render(<DistributionHistoryPanel />);
    expect(
      (await screen.findByTestId("reports-distribution-unapproved-dist_gap")).textContent,
    ).toContain("no approver recorded");
  });

  it("renders every row the ledger returns, not just the first", async () => {
    respond([
      makeRow({ id: "dist_1" }),
      makeRow({ id: "dist_2", recipient: "FBI IC3", tlp_applied: "green" }),
    ]);
    render(<DistributionHistoryPanel />);
    await screen.findByTestId("reports-distributions-list");
    expect(screen.getByTestId("reports-distribution-dist_1")).toBeTruthy();
    expect(screen.getByTestId("reports-distribution-dist_2")).toBeTruthy();
  });

  it("asks for the whole org ledger — no report filter by default", async () => {
    render(<DistributionHistoryPanel />);
    await waitFor(() => expect(listReportDistributions).toHaveBeenCalledWith());
  });
});
