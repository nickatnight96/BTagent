/**
 * EPIC-7 UC-7.1 — per-incident evidence packages on the Audit Ledger page.
 *
 * The auditor-facing contract is: type an incident/resource id, submit, and
 * both the entry list *and* the CSV export narrow to that object. These tests
 * pin the request shape (`incidentId` reaches the API), the export href, and
 * the empty-state wording that distinguishes "nothing matched" from "the
 * ledger is empty".
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const listAuditEntries = vi.fn();
const verifyAuditChain = vi.fn();
const getAuditLineage = vi.fn();

vi.mock("@/api/audit", async () => {
  // auditExportUrl is pure URL construction — exercise the real one so the
  // href assertions below cover encoding too, not just the mock.
  const actual =
    await vi.importActual<typeof import("@/api/audit")>("@/api/audit");
  return {
    ...actual,
    listAuditEntries: (...a: unknown[]) => listAuditEntries(...a),
    verifyAuditChain: (...a: unknown[]) => verifyAuditChain(...a),
    getAuditLineage: (...a: unknown[]) => getAuditLineage(...a),
  };
});

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { AuditLedgerPage } from "@/components/audit/AuditLedgerPage";

const ENTRY = {
  id: "aud_1",
  seq: 1,
  timestamp: "2026-07-01T00:00:00+00:00",
  actor: "usr_1",
  category: "agent_action",
  action: "isolate_host",
  resource: "inv_01H",
  outcome: "success",
  prev_hash: "0".repeat(64),
  hash: "a".repeat(64),
};

function filterFor(id: string) {
  fireEvent.change(screen.getByTestId("audit-incident-filter-input"), {
    target: { value: id },
  });
  fireEvent.submit(screen.getByTestId("audit-incident-filter"));
}

describe("AuditLedgerPage incident filter (UC-7.1)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listAuditEntries.mockResolvedValue({
      items: [ENTRY],
      limit: 100,
      offset: 0,
    });
    verifyAuditChain.mockResolvedValue({ valid: true, errors: [] });
    getAuditLineage.mockResolvedValue({
      nodes: [],
      edges: [],
      intact: true,
      broken_at: null,
    });
  });

  it("loads unfiltered on mount", async () => {
    render(<AuditLedgerPage />);
    await waitFor(() =>
      expect(listAuditEntries).toHaveBeenCalledWith({
        limit: 100,
        incidentId: undefined,
      }),
    );
  });

  it("submitting an id refetches scoped to that incident", async () => {
    render(<AuditLedgerPage />);
    await screen.findByTestId("audit-table");

    filterFor("inv_01H");

    await waitFor(() =>
      expect(listAuditEntries).toHaveBeenLastCalledWith({
        limit: 100,
        incidentId: "inv_01H",
      }),
    );
    expect(
      screen.getByTestId("audit-incident-filter-active").textContent,
    ).toContain("inv_01H");
  });

  it("whitespace around a pasted id is trimmed before it reaches the API", async () => {
    render(<AuditLedgerPage />);
    await screen.findByTestId("audit-table");

    filterFor("  inv_01H  ");

    await waitFor(() =>
      expect(listAuditEntries).toHaveBeenLastCalledWith({
        limit: 100,
        incidentId: "inv_01H",
      }),
    );
  });

  it("retargets the CSV export at the active incident", async () => {
    render(<AuditLedgerPage />);
    const link = await screen.findByTestId("audit-export-link");
    expect(link.getAttribute("href")).toBe("/api/v1/audit/export");
    expect(link.textContent).toContain("Export CSV");

    filterFor("inv_01H");

    await waitFor(() =>
      expect(screen.getByTestId("audit-export-link").getAttribute("href")).toBe(
        "/api/v1/audit/export?incident_id=inv_01H",
      ),
    );
    expect(screen.getByTestId("audit-export-link").textContent).toContain(
      "Export this incident",
    );
  });

  it("clearing restores the unfiltered ledger and export", async () => {
    render(<AuditLedgerPage />);
    await screen.findByTestId("audit-table");
    filterFor("inv_01H");
    await screen.findByTestId("audit-incident-filter-clear");

    fireEvent.click(screen.getByTestId("audit-incident-filter-clear"));

    await waitFor(() =>
      expect(listAuditEntries).toHaveBeenLastCalledWith({
        limit: 100,
        incidentId: undefined,
      }),
    );
    expect(screen.getByTestId("audit-export-link").getAttribute("href")).toBe(
      "/api/v1/audit/export",
    );
    expect(screen.queryByTestId("audit-incident-filter-active")).toBeNull();
  });

  it("an id needing encoding is escaped in the export href", async () => {
    render(<AuditLedgerPage />);
    await screen.findByTestId("audit-table");

    filterFor("inv a&b");

    await waitFor(() =>
      expect(screen.getByTestId("audit-export-link").getAttribute("href")).toBe(
        "/api/v1/audit/export?incident_id=inv%20a%26b",
      ),
    );
  });

  it("distinguishes an empty filter result from an empty ledger", async () => {
    listAuditEntries.mockResolvedValue({ items: [], limit: 100, offset: 0 });
    render(<AuditLedgerPage />);
    expect(await screen.findByText("No audit entries.")).toBeTruthy();

    filterFor("inv_missing");

    expect(
      await screen.findByText("No audit entries for inv_missing."),
    ).toBeTruthy();
  });
});
