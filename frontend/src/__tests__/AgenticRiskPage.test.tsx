/**
 * RTL tests for the AgenticRiskPage (#121 Phase B):
 *  1. Findings render with per-detection bucket counts.
 *  2. Clicking a bucket tile filters the list; clicking again clears.
 *  3. Run agentic hunt triggers the endpoint and refreshes findings.
 *  4. Empty state before any findings.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const mockList = vi.fn();
const mockRun = vi.fn();

vi.mock("@/api/agentic", () => ({
  listAgenticFindings: (...a: unknown[]) => mockList(...a),
}));
vi.mock("@/api/hunt", () => ({
  runAgenticHunt: (...a: unknown[]) => mockRun(...a),
}));
vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

// Live-refresh wiring (#121 Phase B): capture the registered refetch so the
// test can simulate a WS-pushed finding event.
const mockLiveRefresh = vi.fn();
vi.mock("@/hooks/useLiveEventRefresh", () => ({
  useLiveEventRefresh: (...a: unknown[]) => mockLiveRefresh(...a),
}));
vi.mock("@/components/hunt/HuntTriagePage", () => ({
  HUNT_FINDING_EVENTS: ["hunt_finding_created", "hunt_finding_updated"],
}));

import {
  AgenticRiskPage,
  bucketOf,
  buildInjectionTimeline,
  buildDriftInventory,
} from "@/components/agentic/AgenticRiskPage";

function finding(id: string, detection: string, severity = "high") {
  return {
    id,
    org_id: "org_default",
    source: "agentic",
    domain: "agentic",
    title: `Finding ${id} (${detection})`,
    description: "",
    severity,
    confidence: 0.8,
    technique_ids: ["T1059"],
    entities: [],
    observables: [],
    state: "new",
    cluster_id: null,
    suppressed_by: null,
    investigation_id: null,
    evidence: { detection },
    created_at: "2026-07-23T06:00:00Z",
    updated_at: "2026-07-23T06:00:00Z",
  };
}

const FINDINGS = [
  {
    ...finding("hfnd_pi", "prompt_injection", "critical"),
    created_at: "2026-07-23T06:00:00Z",
    evidence: {
      detection: "prompt_injection",
      matched_patterns: ["instruction_override.ignore_previous", "jailbreak.dan_phrase"],
      redacted_excerpts: ["Ignore previous instructions and […]"],
    },
  },
  finding("hfnd_shadow", "shadow_workload"),
  finding("hfnd_exfil", "llm_exfil", "critical"),
  finding("hfnd_ident", "identity_privilege_divergence"),
  {
    ...finding("hfnd_pi2", "prompt_injection", "high"),
    created_at: "2026-07-23T07:00:00Z",
    evidence: { detection: "prompt_injection", matched_patterns: ["role_hijack.act_as"] },
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <AgenticRiskPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue({
    clusters: [],
    findings: FINDINGS,
    total_clusters: 0,
    total_findings: 5,
  });
  mockRun.mockResolvedValue({ findings_created: 4 });
});

describe("bucketOf", () => {
  it("maps evidence.detection to the four Phase A buckets", () => {
    expect(bucketOf(finding("a", "prompt_injection") as never)).toBe("prompt_injection");
    expect(bucketOf(finding("b", "shadow_agent_registration") as never)).toBe("shadow_agent");
    expect(bucketOf(finding("c", "identity_tool_misuse") as never)).toBe("identity_abuse");
    // Regression: the A3 detector's real evidence values must bucket correctly.
    expect(bucketOf(finding("c2", "agent_identity_abuse") as never)).toBe("identity_abuse");
    expect(bucketOf(finding("c3", "agent_identity_abuse.unregistered") as never)).toBe(
      "identity_abuse",
    );
    expect(bucketOf(finding("d", "llm_exfil") as never)).toBe("llm_exfil");
    expect(bucketOf(finding("e", "mystery") as never)).toBe("other");
  });
});

describe("AgenticRiskPage", () => {
  it("renders findings and per-bucket counts", async () => {
    renderPage();

    expect(await screen.findByTestId("agentic-finding-hfnd_pi")).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith({ state: "active", page_size: 200 });
    expect(screen.getByTestId("bucket-prompt_injection")).toHaveTextContent("2");
    expect(screen.getByTestId("bucket-shadow_agent")).toHaveTextContent("1");
    expect(screen.getByTestId("bucket-identity_abuse")).toHaveTextContent("1");
    expect(screen.getByTestId("bucket-llm_exfil")).toHaveTextContent("1");
    expect(screen.getByTestId("agentic-finding-hfnd_exfil")).toHaveTextContent("critical");
  });

  it("bucket tiles filter the list and toggle off", async () => {
    renderPage();
    await screen.findByTestId("agentic-finding-hfnd_pi");

    fireEvent.click(screen.getByTestId("bucket-llm_exfil"));
    expect(screen.getByTestId("agentic-finding-hfnd_exfil")).toBeInTheDocument();
    expect(screen.queryByTestId("agentic-finding-hfnd_pi")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("bucket-llm_exfil"));
    expect(screen.getByTestId("agentic-finding-hfnd_pi")).toBeInTheDocument();
  });

  it("run button triggers the hunt and refreshes", async () => {
    renderPage();
    await screen.findByTestId("agentic-finding-hfnd_pi");
    expect(mockList).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId("run-agentic-hunt"));

    await waitFor(() => expect(mockRun).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(2));
  });

  it("renders the injection timeline newest-first with pattern chips + excerpt", async () => {
    renderPage();
    const timeline = await screen.findByTestId("injection-timeline");

    const entries = buildInjectionTimeline(FINDINGS as never);
    expect(entries.map((e) => e.finding_id)).toEqual(["hfnd_pi2", "hfnd_pi"]);

    const first = screen.getByTestId("injection-entry-hfnd_pi");
    expect(first).toHaveTextContent("instruction_override.ignore_previous");
    expect(first).toHaveTextContent("jailbreak.dan_phrase");
    expect(first).toHaveTextContent("Ignore previous instructions and […]");
    expect(timeline).toHaveTextContent("Prompt-injection timeline");
    // Entry without excerpts renders chips but no excerpt block.
    expect(screen.getByTestId("injection-entry-hfnd_pi2")).toHaveTextContent(
      "role_hijack.act_as",
    );
  });

  it("hides the timeline when there are no injection findings", async () => {
    mockList.mockResolvedValue({
      clusters: [],
      findings: [finding("hfnd_only_exfil", "llm_exfil")],
      total_clusters: 0,
      total_findings: 1,
    });
    renderPage();
    await screen.findByTestId("agentic-finding-hfnd_only_exfil");
    expect(screen.queryByTestId("injection-timeline")).not.toBeInTheDocument();
  });

  it("renders the identity-drift inventory from A3 evidence", async () => {
    const drift = {
      ...finding("hfnd_drift", "agent_identity_abuse", "high"),
      created_at: "2026-07-23T08:00:00Z",
      evidence: {
        detection: "agent_identity_abuse",
        agent_identity_ref: "arn:aws:iam::1:role/TriageAgent",
        declared_role: "arn:aws:iam::1:role/TriageAgent",
        observed_role: "arn:aws:iam::1:role/AdminRole",
        invoked_tool: "kb_search",
        out_of_toolset: false,
        role_mismatch: true,
        privileged_escalation: true,
        reasons: ["role_mismatch", "privileged_escalation"],
      },
    };
    mockList.mockResolvedValue({
      clusters: [],
      findings: [drift],
      total_clusters: 0,
      total_findings: 1,
    });
    renderPage();

    const entry = await screen.findByTestId("drift-entry-hfnd_drift");
    expect(entry).toHaveTextContent("arn:aws:iam::1:role/TriageAgent");
    expect(entry).toHaveTextContent("arn:aws:iam::1:role/AdminRole");
    expect(entry).toHaveTextContent("role_mismatch");
    expect(entry).toHaveTextContent("privileged_escalation");
    expect(entry).toHaveTextContent("kb_search");

    // Helper falls back to boolean flags when reasons[] is absent.
    const noReasons = buildDriftInventory([
      {
        ...drift,
        evidence: { ...drift.evidence, reasons: undefined },
      },
    ] as never);
    expect(noReasons[0]?.reasons).toEqual(["role_mismatch", "privileged_escalation"]);
  });

  it("hides the drift inventory when there are no identity findings", async () => {
    mockList.mockResolvedValue({
      clusters: [],
      findings: [finding("hfnd_pi_only", "prompt_injection")],
      total_clusters: 0,
      total_findings: 1,
    });
    renderPage();
    await screen.findByTestId("agentic-finding-hfnd_pi_only");
    expect(screen.queryByTestId("drift-inventory")).not.toBeInTheDocument();
  });

  it("registers live refresh on finding events and refetches when fired", async () => {
    renderPage();
    await screen.findByTestId("agentic-finding-hfnd_pi");
    expect(mockLiveRefresh).toHaveBeenCalled();
    const [refetch, events] = mockLiveRefresh.mock.calls[0] as [() => void, string[]];
    expect(events).toContain("hunt_finding_created");

    expect(mockList).toHaveBeenCalledTimes(1);
    refetch(); // simulate a WS-pushed finding event
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(2));
  });

  it("shows the empty state when there are no findings", async () => {
    mockList.mockResolvedValue({
      clusters: [],
      findings: [],
      total_clusters: 0,
      total_findings: 0,
    });
    renderPage();

    expect(await screen.findByTestId("agentic-empty")).toHaveTextContent(
      "No active agentic findings",
    );
  });
});
