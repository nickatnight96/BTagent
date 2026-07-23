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

import { AgenticRiskPage, bucketOf } from "@/components/agentic/AgenticRiskPage";

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
  finding("hfnd_pi", "prompt_injection", "critical"),
  finding("hfnd_shadow", "shadow_workload"),
  finding("hfnd_exfil", "llm_exfil", "critical"),
  finding("hfnd_ident", "identity_privilege_divergence"),
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
    total_findings: 4,
  });
  mockRun.mockResolvedValue({ findings_created: 4 });
});

describe("bucketOf", () => {
  it("maps evidence.detection to the four Phase A buckets", () => {
    expect(bucketOf(finding("a", "prompt_injection") as never)).toBe("prompt_injection");
    expect(bucketOf(finding("b", "shadow_agent_registration") as never)).toBe("shadow_agent");
    expect(bucketOf(finding("c", "identity_tool_misuse") as never)).toBe("identity_abuse");
    expect(bucketOf(finding("d", "llm_exfil") as never)).toBe("llm_exfil");
    expect(bucketOf(finding("e", "mystery") as never)).toBe("other");
  });
});

describe("AgenticRiskPage", () => {
  it("renders findings and per-bucket counts", async () => {
    renderPage();

    expect(await screen.findByTestId("agentic-finding-hfnd_pi")).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith({ state: "active", page_size: 200 });
    expect(screen.getByTestId("bucket-prompt_injection")).toHaveTextContent("1");
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
