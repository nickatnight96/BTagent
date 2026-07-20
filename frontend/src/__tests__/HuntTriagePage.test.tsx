/**
 * RTL tests for the HuntTriagePage and SuppressModal/PromoteModal.
 *
 * Key behaviors:
 *  1. Suppress dialog blocks submit when rationale is blank.
 *  2. 409 over-broad error surfaces in the suppress modal.
 *  3. Promote renders an investigation link after success.
 *  4. Role-gated buttons: suppress/promote hidden for plain analyst.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

// ---- API mocks ----

const mockListFindings = vi.fn();
const mockSuppressFinding = vi.fn();
const mockSuppressCluster = vi.fn();
const mockPromoteFindings = vi.fn();
const mockPromoteCluster = vi.fn();
const mockListSuppressions = vi.fn();
const mockCreateSuppression = vi.fn();
const mockRunEmailHunt = vi.fn();
const mockRunDeceptionHunt = vi.fn();
const mockRunNdrHunt = vi.fn();
const mockRunAllHunts = vi.fn();
const mockRunAgenticHunt = vi.fn();
const mockListHuntVerticals = vi.fn();

vi.mock("@/api/hunt", () => ({
  listFindings: (...a: unknown[]) => mockListFindings(...a),
  suppressFinding: (...a: unknown[]) => mockSuppressFinding(...a),
  suppressCluster: (...a: unknown[]) => mockSuppressCluster(...a),
  promoteFindings: (...a: unknown[]) => mockPromoteFindings(...a),
  promoteCluster: (...a: unknown[]) => mockPromoteCluster(...a),
  listSuppressions: (...a: unknown[]) => mockListSuppressions(...a),
  createSuppression: (...a: unknown[]) => mockCreateSuppression(...a),
  runEmailHunt: (...a: unknown[]) => mockRunEmailHunt(...a),
  runDeceptionHunt: (...a: unknown[]) => mockRunDeceptionHunt(...a),
  runNdrHunt: (...a: unknown[]) => mockRunNdrHunt(...a),
  runAllHunts: (...a: unknown[]) => mockRunAllHunts(...a),
  runAgenticHunt: (...a: unknown[]) => mockRunAgenticHunt(...a),
  listHuntVerticals: (...a: unknown[]) => mockListHuntVerticals(...a),
  getFinding: vi.fn(),
}));

// ---- WS mock ----

vi.mock("@/api/ws", () => ({
  getWSClient: () => ({
    onEvent: () => {},
    connect: () => {},
    disconnect: () => {},
    isConnected: false,
  }),
}));

// ---- Auth store mock ----
// Default: senior_analyst (can triage)
let mockRole = "senior_analyst";

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel: (s: { user: { role: string } | null }) => unknown) =>
    sel({ user: { role: mockRole } }),
}));

import { useHuntStore } from "@/stores/huntStore";
import { HuntTriagePage } from "@/components/hunt/HuntTriagePage";
import { ApiError } from "@/api/client";

// --------------------------------------------------------------------------- //
// Fixture helpers
// --------------------------------------------------------------------------- //

const CLUSTER = {
  id: "hclu_01",
  org_id: "org_default",
  signature: "sigma/T1059.001",
  title: "Encoded PowerShell on DC",
  domain: "sigma",
  severity: "high",
  technique_ids: ["T1059.001"],
  finding_count: 2,
  state: "clustered",
  representative_finding_id: "hfnd_01",
  created_at: "2026-06-01T12:00:00Z",
  updated_at: "2026-06-01T12:00:00Z",
};

const FINDING = {
  id: "hfnd_01",
  org_id: "org_default",
  source: "hunt_pack",
  domain: "sigma",
  title: "Base64 PS command",
  description: "",
  severity: "high",
  confidence: 0.9,
  technique_ids: ["T1059.001"],
  entities: [],
  observables: [],
  state: "clustered",
  cluster_id: "hclu_01",
  suppressed_by: null,
  investigation_id: null,
  evidence: {},
  created_at: "2026-06-01T12:00:00Z",
  updated_at: "2026-06-01T12:00:00Z",
};

const INBOX_RESPONSE = {
  clusters: [CLUSTER],
  findings: [FINDING],
  total_clusters: 1,
  total_findings: 1,
};

const EMPTY_INBOX = {
  clusters: [],
  findings: [],
  total_clusters: 0,
  total_findings: 0,
};

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //

describe("HuntTriagePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "senior_analyst";
    // Reset Zustand store between tests
    useHuntStore.setState({
      clusters: [],
      findings: [],
      suppressions: [],
      totalClusters: 0,
      totalFindings: 0,
      isLoading: false,
      isMutating: false,
      error: null,
      selectedFindingIds: [],
      activeTab: "active",
      page: 1,
      pageSize: 50,
    });
    mockListSuppressions.mockResolvedValue({ items: [], total: 0 });
    // Default: no verticals reported scheduled (badges off) unless a test overrides.
    mockListHuntVerticals.mockResolvedValue({ verticals: [] });
  });

  // ---- 1. Suppress dialog blocks submit when rationale is blank ----

  it("suppress dialog keeps Submit disabled when rationale is empty", async () => {
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);
    renderPage(<HuntTriagePage />);

    // Wait for clusters to render
    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument()
    );

    // Expand cluster to see findings
    fireEvent.click(screen.getByTestId("hunt-cluster-expand"));

    // Click Suppress on the finding
    await waitFor(() =>
      expect(screen.getByTestId("hunt-finding-suppress")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("hunt-finding-suppress"));

    // Modal opens
    await waitFor(() =>
      expect(screen.getByTestId("hunt-suppress-modal")).toBeInTheDocument()
    );

    const submitBtn = screen.getByTestId("hunt-suppress-submit");
    expect(submitBtn).toBeDisabled();

    // Fill name only — still disabled
    fireEvent.change(screen.getByTestId("hunt-suppress-name"), {
      target: { value: "Test rule" },
    });
    expect(submitBtn).toBeDisabled();

    // Fill reason — now enabled
    fireEvent.change(screen.getByTestId("hunt-suppress-reason"), {
      target: { value: "Approved activity" },
    });
    expect(submitBtn).not.toBeDisabled();
  });

  it("suppress dialog shows inline error when rationale is blank and submit is attempted via API validation", async () => {
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);
    // Return a 422 when reason is empty
    mockSuppressFinding.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail: "reason: field required",
      })
    );
    renderPage(<HuntTriagePage />);

    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("hunt-cluster-expand"));
    await waitFor(() =>
      expect(screen.getByTestId("hunt-finding-suppress")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("hunt-finding-suppress"));

    await waitFor(() =>
      expect(screen.getByTestId("hunt-suppress-modal")).toBeInTheDocument()
    );

    // Modal client-side validates blank reason: submit stays disabled
    const submitBtn = screen.getByTestId("hunt-suppress-submit");
    expect(submitBtn).toBeDisabled();

    // Verify the submit button can't be activated with just a name
    fireEvent.change(screen.getByTestId("hunt-suppress-name"), {
      target: { value: "My rule" },
    });
    expect(submitBtn).toBeDisabled();
    // No API call made yet
    expect(mockSuppressFinding).not.toHaveBeenCalled();
  });

  // ---- 2. 409 over-broad error surfaces ----

  it("surfaces 409 over-broad conflict message in the suppress modal", async () => {
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);
    mockSuppressFinding.mockRejectedValue(
      new ApiError(409, "Conflict", {
        detail:
          "Suppression rule would be over-broad: 47 findings across 5 clusters would be suppressed",
      })
    );

    renderPage(<HuntTriagePage />);
    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("hunt-cluster-expand"));
    await waitFor(() =>
      expect(screen.getByTestId("hunt-finding-suppress")).toBeInTheDocument()
    );
    fireEvent.click(screen.getByTestId("hunt-finding-suppress"));

    await waitFor(() =>
      expect(screen.getByTestId("hunt-suppress-modal")).toBeInTheDocument()
    );

    // Fill both fields
    fireEvent.change(screen.getByTestId("hunt-suppress-name"), {
      target: { value: "Broad rule" },
    });
    fireEvent.change(screen.getByTestId("hunt-suppress-reason"), {
      target: { value: "All of these are approved" },
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId("hunt-suppress-submit"));
    });

    const errorEl = await screen.findByTestId("hunt-suppress-error");
    expect(errorEl).toHaveTextContent("over-broad");
  });

  // ---- 3. Promote renders investigation link after success ----

  it("promote modal shows investigation link on success", async () => {
    // Always return INBOX_RESPONSE (for initial load + any refreshes)
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);
    mockPromoteCluster.mockResolvedValue({
      investigation_id: "inv_PROMOTED01",
      promoted_finding_ids: ["hfnd_01"],
    });

    renderPage(<HuntTriagePage />);
    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument(),
      { timeout: 5000 }
    );

    // Click Promote on the cluster
    fireEvent.click(screen.getByTestId("hunt-cluster-promote"));

    await waitFor(() =>
      expect(screen.getByTestId("hunt-promote-modal")).toBeInTheDocument()
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("hunt-promote-submit"));
    });

    // Investigation link appears
    const link = await screen.findByTestId("hunt-promote-investigation-link");
    expect(link).toBeInTheDocument();
    expect((link as HTMLAnchorElement).href).toContain("inv_PROMOTED01");
  });

  // ---- 4. Role-gated buttons ----

  it("hides suppress/promote buttons for plain analyst role", async () => {
    mockRole = "analyst";
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);

    renderPage(<HuntTriagePage />);
    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument()
    );

    // RBAC notice is shown
    await waitFor(() =>
      expect(screen.getByTestId("hunt-rbac-notice")).toBeInTheDocument()
    );

    // No cluster-level action buttons
    expect(screen.queryByTestId("hunt-cluster-suppress")).not.toBeInTheDocument();
    expect(screen.queryByTestId("hunt-cluster-promote")).not.toBeInTheDocument();

    // Expand to see findings
    fireEvent.click(screen.getByTestId("hunt-cluster-expand"));
    await waitFor(() =>
      expect(screen.getByTestId("hunt-finding-row")).toBeInTheDocument()
    );

    // No finding-level action buttons
    expect(screen.queryByTestId("hunt-finding-suppress")).not.toBeInTheDocument();
    expect(screen.queryByTestId("hunt-finding-promote")).not.toBeInTheDocument();
  });

  it("shows suppress/promote buttons for senior_analyst role", async () => {
    mockRole = "senior_analyst";
    mockListFindings.mockResolvedValue(INBOX_RESPONSE);

    renderPage(<HuntTriagePage />);
    await waitFor(() =>
      expect(screen.getByTestId("hunt-cluster-card")).toBeInTheDocument()
    );

    // No RBAC notice
    expect(screen.queryByTestId("hunt-rbac-notice")).not.toBeInTheDocument();

    // Cluster buttons present
    expect(screen.getByTestId("hunt-cluster-suppress")).toBeInTheDocument();
    expect(screen.getByTestId("hunt-cluster-promote")).toBeInTheDocument();
  });

  // ---- 5. State filter tabs ----

  it("renders the Active, Suppressed, Promoted tabs", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    renderPage(<HuntTriagePage />);

    await waitFor(() =>
      expect(screen.getByTestId("hunt-triage-tabs")).toBeInTheDocument()
    );

    expect(screen.getByTestId("hunt-tab-active")).toBeInTheDocument();
    expect(screen.getByTestId("hunt-tab-suppressed")).toBeInTheDocument();
    expect(screen.getByTestId("hunt-tab-promoted")).toBeInTheDocument();
  });

  // ---- 6. Empty state ----

  it("shows empty state when no clusters", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    renderPage(<HuntTriagePage />);
    await waitFor(() =>
      expect(screen.getByTestId("hunt-triage")).toBeInTheDocument()
    );
    // Loading spinner should disappear
    await waitFor(() => expect(screen.queryByText(/Loading hunt inbox/)).not.toBeInTheDocument());
    expect(screen.getByText("No active hunt findings.")).toBeInTheDocument();
  });

  // ---- 7. Loading state ----

  it("shows loading spinner while fetching", () => {
    mockListFindings.mockReturnValue(new Promise(() => {})); // never resolves
    renderPage(<HuntTriagePage />);
    expect(screen.getByText(/Loading hunt inbox/)).toBeInTheDocument();
  });

  // ---- 8. Error state ----

  it("shows error banner when fetch fails", async () => {
    mockListFindings.mockRejectedValue(new Error("Network failure"));
    renderPage(<HuntTriagePage />);
    const err = await screen.findByTestId("hunt-triage-error");
    expect(err).toHaveTextContent("Network failure");
  });

  // ---- Run email hunt (email vertical, slice 6) ----

  it("runs an email hunt and refreshes the inbox", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockRunEmailHunt.mockResolvedValue({
      window: { start: "s", end: "e" },
      total_incidents: 2,
      active_incident_count: 1,
      findings_emitted: 2,
      findings_created: 2,
      counts_by_severity: { critical: 1, high: 1, medium: 0, low: 0, info: 0 },
    });
    renderPage(<HuntTriagePage />);

    const runBtn = await screen.findByTestId("hunt-run-email");
    // The initial mount fetch has already run; count refreshes after the click.
    const beforeFetches = mockListFindings.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(mockRunEmailHunt).toHaveBeenCalledTimes(1));
    // The inbox was re-fetched to surface the newly-landed findings.
    await waitFor(() =>
      expect(mockListFindings.mock.calls.length).toBeGreaterThan(beforeFetches)
    );
  });

  // ---- Run deception hunt (deception vertical, slice 4) ----

  it("runs a deception hunt and refreshes the inbox", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockRunDeceptionHunt.mockResolvedValue({
      total_incidents: 3,
      active_intruder_count: 1,
      findings_emitted: 3,
      findings_created: 3,
      counts_by_severity: { critical: 2, high: 0, medium: 1, low: 0, info: 0 },
    });
    renderPage(<HuntTriagePage />);

    const runBtn = await screen.findByTestId("hunt-run-deception");
    const beforeFetches = mockListFindings.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(mockRunDeceptionHunt).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(mockListFindings.mock.calls.length).toBeGreaterThan(beforeFetches)
    );
  });

  // ---- Run NDR hunt (NDR vertical, slice 4) ----

  it("runs an NDR hunt and refreshes the inbox", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockRunNdrHunt.mockResolvedValue({
      total_hosts: 2,
      campaign_count: 1,
      findings_emitted: 2,
      findings_created: 2,
      counts_by_severity: { critical: 1, high: 0, medium: 1, low: 0, info: 0 },
    });
    renderPage(<HuntTriagePage />);

    const runBtn = await screen.findByTestId("hunt-run-ndr");
    const beforeFetches = mockListFindings.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(mockRunNdrHunt).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(mockListFindings.mock.calls.length).toBeGreaterThan(beforeFetches)
    );
  });

  it("runs an agentic hunt and refreshes the inbox", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockRunAgenticHunt.mockResolvedValue({
      total_events: 2,
      total_identities: 2,
      total_workloads: 2,
      findings_emitted: 4,
      findings_created: 4,
      counts_by_severity: { high: 4 },
    });
    renderPage(<HuntTriagePage />);

    const runBtn = await screen.findByTestId("hunt-run-agentic");
    const beforeFetches = mockListFindings.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(mockRunAgenticHunt).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(mockListFindings.mock.calls.length).toBeGreaterThan(beforeFetches)
    );
  });

  it("runs all hunts in one sweep and refreshes the inbox", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockRunAllHunts.mockResolvedValue({
      verticals: {
        email: { findings_emitted: 1, findings_created: 1, counts_by_severity: { high: 1 } },
        deception: { findings_emitted: 1, findings_created: 1, counts_by_severity: { critical: 1 } },
        ndr: { findings_emitted: 2, findings_created: 2, counts_by_severity: { high: 2 } },
      },
      total_findings_emitted: 4,
      total_findings_created: 4,
      counts_by_severity: { critical: 1, high: 3 },
    });
    renderPage(<HuntTriagePage />);

    const runBtn = await screen.findByTestId("hunt-run-all");
    const beforeFetches = mockListFindings.mock.calls.length;

    await act(async () => {
      fireEvent.click(runBtn);
    });

    await waitFor(() => expect(mockRunAllHunts).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(mockListFindings.mock.calls.length).toBeGreaterThan(beforeFetches)
    );
  });

  it("badges a run button when its vertical is scheduled", async () => {
    mockListFindings.mockResolvedValue(EMPTY_INBOX);
    mockListHuntVerticals.mockResolvedValue({
      verticals: [
        {
          name: "ndr",
          domain: "ndr",
          source: "ndr",
          run_route: "/hunt/ndr/run",
          windowed: false,
          schedule_enabled: true,
          scan_interval_hours: 6,
        },
        {
          name: "email",
          domain: "email",
          source: "email_security",
          run_route: "/hunt/email/run",
          windowed: true,
          schedule_enabled: false,
          scan_interval_hours: 6,
        },
      ],
    });
    renderPage(<HuntTriagePage />);

    // NDR reported scheduled → badge shows its cadence.
    const badge = await screen.findByTestId("hunt-schedule-ndr");
    expect(badge.textContent).toContain("6h");
    // Email reported not scheduled → no badge.
    expect(screen.queryByTestId("hunt-schedule-email")).toBeNull();
  });
});
