/**
 * Data retention posture + manual cleanup (#418).
 *
 * `GET /config/retention` and `POST /config/retention/run` shipped with no
 * consumer, so how long incident data is kept — and whether the audit ledger
 * still meets its compliance window — could only be asked with curl.
 *
 * The run permanently deletes events. So the cases that carry weight are the
 * ones stopping it happening by accident, and the ones making sure the panel
 * never overstates what a run did.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const getRetentionStats = vi.fn();
const runRetentionCleanup = vi.fn();
let mockRole = "admin";

vi.mock("@/api/configSchema", () => ({
  getRetentionStats: (...a: unknown[]) => getRetentionStats(...a),
  runRetentionCleanup: (...a: unknown[]) => runRetentionCleanup(...a),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) => selector({ user: { role: mockRole } }),
}));

import { RetentionPanel } from "@/components/settings/RetentionPanel";

const STATS = {
  events: { total: 120_000, stale: 4_200, retention_days: 90 },
  audit_logs: { total: 8_000, retention_years: 7, policy: "never_delete" },
  investigations: { total: 340, archivable: 12, retention_days: 90 },
};

function runResult(compliant = true, issues: string[] = []) {
  return {
    events: { deleted_count: 4_200, retention_days: 90, cutoff: "2026-04-29T00:00:00Z" },
    investigations: { archived_count: 12, retention_days: 90, cutoff: "2026-04-29T00:00:00Z" },
    audit_verification: {
      total_entries: 8_000,
      earliest_entry: "2020-01-01T00:00:00Z",
      latest_entry: "2026-07-28T00:00:00Z",
      retention_years: 7,
      compliance_boundary: "2019-07-28T00:00:00Z",
      compliant,
      issues,
    },
  };
}

describe("RetentionPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "admin";
    getRetentionStats.mockResolvedValue(STATS);
    runRetentionCleanup.mockResolvedValue(runResult());
  });

  it("shows what is held and what is past its window", async () => {
    render(<RetentionPanel />);
    const events = await screen.findByTestId("retention-events");
    expect(events.textContent).toContain("4,200");
    expect(events.textContent).toContain("past 90d");
    expect(screen.getByTestId("retention-investigations").textContent).toContain("12");
  });

  it("says the audit ledger is never pruned by the cleanup", async () => {
    // Without this, an operator could reasonably assume a retention run
    // touches the evidence chain. It doesn't, and that should be visible.
    render(<RetentionPanel />);
    expect((await screen.findByTestId("retention-audit")).textContent).toContain(
      "never deleted by cleanup",
    );
  });

  it("does not run on the first click", async () => {
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    expect(runRetentionCleanup).not.toHaveBeenCalled();
    expect(screen.getByTestId("retention-confirm")).toBeTruthy();
  });

  it("states the exact irreversible cost in the confirmation", async () => {
    // "Are you sure?" is useless here. The operator needs the counts.
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    const confirm = screen.getByTestId("retention-confirm");
    expect(confirm.textContent).toContain("4,200 events");
    expect(confirm.textContent).toContain("12 investigations");
    expect(confirm.textContent).toContain("cannot be undone");
  });

  it("cancelling leaves everything alone", async () => {
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    fireEvent.click(screen.getByTestId("retention-run-cancel"));
    expect(runRetentionCleanup).not.toHaveBeenCalled();
    expect(screen.queryByTestId("retention-confirm")).toBeNull();
  });

  it("reports the counts actually affected and refreshes the posture", async () => {
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    fireEvent.click(screen.getByTestId("retention-run-confirm"));

    const result = await screen.findByTestId("retention-result");
    expect(result.textContent).toContain("4,200");
    expect(result.textContent).toContain("12");
    // The displayed stats are stale the moment a run succeeds.
    await waitFor(() => expect(getRetentionStats).toHaveBeenCalledTimes(2));
  });

  it("surfaces a failed audit-compliance check as the finding it is", async () => {
    runRetentionCleanup.mockResolvedValue(
      runResult(false, ["Earliest audit entry is inside the compliance boundary"]),
    );
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    fireEvent.click(screen.getByTestId("retention-run-confirm"));

    expect((await screen.findByTestId("retention-audit-compliance")).textContent).toContain(
      "NOT within its compliance window",
    );
    expect(screen.getByTestId("retention-audit-issues").textContent).toContain(
      "compliance boundary",
    );
  });

  it("says nothing was deleted when the run fails", async () => {
    // An ambiguous error after a destructive action is the worst kind: the
    // operator has to know whether data went.
    runRetentionCleanup.mockRejectedValue(new Error("boom"));
    render(<RetentionPanel />);
    fireEvent.click(await screen.findByTestId("retention-run"));
    fireEvent.click(screen.getByTestId("retention-run-confirm"));

    expect((await screen.findByTestId("retention-error")).textContent).toContain(
      "nothing was deleted",
    );
    expect(screen.queryByTestId("retention-result")).toBeNull();
  });

  it("shows non-admins the posture but no run button", async () => {
    // config:view is analyst+; config:edit is admin. Knowing the retention
    // posture isn't privileged, running the cleanup is.
    mockRole = "senior_analyst";
    render(<RetentionPanel />);
    await screen.findByTestId("retention-events");
    expect(screen.queryByTestId("retention-run")).toBeNull();
  });

  it("hides itself if the stats fetch fails", async () => {
    getRetentionStats.mockRejectedValue(new Error("boom"));
    render(<RetentionPanel />);
    await waitFor(() => expect(getRetentionStats).toHaveBeenCalled());
    expect(screen.queryByTestId("retention-panel")).toBeNull();
  });
});
