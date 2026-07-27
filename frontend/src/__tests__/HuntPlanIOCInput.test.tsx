/**
 * #99 — IOC input on the Hunt Planner.
 *
 * An analyst frequently holds only indicators (from an advisory, a peer, an
 * alert) and no actor name or technique id. These tests pin that path: bare
 * values are typed, the type is inferred, and the inference is shown back
 * before anything is sent — an "other" classification produces no hypothesis
 * server-side, so the analyst needs to see it rather than wonder why their
 * input was ignored.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

const generateHuntPlan = vi.fn();
const listHuntPlans = vi.fn();
const listHuntPlanRuns = vi.fn();

vi.mock("@/api/hunts", async () => {
  // inferIOCType is pure — exercise the real implementation so the type
  // assertions below test the classifier, not a stub of it.
  const actual =
    await vi.importActual<typeof import("@/api/hunts")>("@/api/hunts");
  return {
    ...actual,
    generateHuntPlan: (...a: unknown[]) => generateHuntPlan(...a),
    listHuntPlans: (...a: unknown[]) => listHuntPlans(...a),
    listHuntPlanRuns: (...a: unknown[]) => listHuntPlanRuns(...a),
  };
});

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { HuntPlanPage } from "@/components/hunts/HuntPlanPage";
import { inferIOCType } from "@/api/hunts";

const PLAN = {
  id: "hunt_1",
  org_id: "org_default",
  state: "ready",
  input: { adversaries: [], ttps: [], iocs: [] },
  executive_summary: {
    adversary_profile: "",
    scope_description: "",
    success_criteria: "",
    estimated_effort_hours: null,
    coverage_delta: {},
  },
  hypotheses: [],
  ttp_entries: [],
  created_at: "2026-07-01T00:00:00+00:00",
};

function renderPage() {
  return render(
    <MemoryRouter>
      <HuntPlanPage />
    </MemoryRouter>,
  );
}

describe("inferIOCType", () => {
  it("classifies the common indicator shapes", () => {
    expect(inferIOCType("8.8.8.8")).toBe("ip");
    expect(inferIOCType("evil.example.com")).toBe("domain");
    expect(inferIOCType("https://evil.example.com/x")).toBe("url");
    expect(inferIOCType("attacker@evil.com")).toBe("email");
    expect(inferIOCType("CVE-2024-3094")).toBe("cve");
    expect(inferIOCType("/usr/bin/evil")).toBe("file_path");
    expect(inferIOCType("C:\\Windows\\evil.exe")).toBe("file_path");
  });

  it("distinguishes hash lengths", () => {
    expect(inferIOCType("d".repeat(32))).toBe("hash_md5");
    expect(inferIOCType("d".repeat(40))).toBe("hash_sha1");
    expect(inferIOCType("d".repeat(64))).toBe("hash_sha256");
  });

  it("does not mistake an IP for a domain", () => {
    // The domain pattern would otherwise match dotted quads, silently
    // mapping an IP to the DNS technique instead of Web Protocols.
    expect(inferIOCType("192.168.1.1")).toBe("ip");
  });

  it("falls back to 'other' rather than guessing", () => {
    expect(inferIOCType("just some words")).toBe("other");
    expect(inferIOCType("!!!")).toBe("other");
  });

  it("tolerates surrounding whitespace", () => {
    expect(inferIOCType("  8.8.8.8  ")).toBe("ip");
  });
});

describe("HuntPlanPage IOC input (#99)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    generateHuntPlan.mockResolvedValue(PLAN);
    listHuntPlans.mockResolvedValue({ items: [], total: 0 });
    listHuntPlanRuns.mockResolvedValue({ items: [], total: 0 });
  });

  it("sends typed IOCs derived from bare values", async () => {
    renderPage();
    fireEvent.change(screen.getByTestId("plan-iocs-input"), {
      target: { value: "evil.example.com, CVE-2024-3094" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    await waitFor(() =>
      expect(generateHuntPlan).toHaveBeenCalledWith({
        adversaries: [],
        ttps: [],
        iocs: [
          { type: "domain", value: "evil.example.com" },
          { type: "cve", value: "CVE-2024-3094" },
        ],
      }),
    );
  });

  it("enables generation on IOCs alone — no adversary or TTP needed", async () => {
    renderPage();
    expect(screen.getByTestId("generate-plan")).toBeDisabled();

    fireEvent.change(screen.getByTestId("plan-iocs-input"), {
      target: { value: "8.8.8.8" },
    });
    await waitFor(() =>
      expect(screen.getByTestId("generate-plan")).not.toBeDisabled(),
    );
  });

  it("shows the inferred type back before sending", async () => {
    renderPage();
    fireEvent.change(screen.getByTestId("plan-iocs-input"), {
      target: { value: "8.8.8.8 nonsense-value" },
    });

    const preview = await screen.findByTestId("plan-iocs-preview");
    expect(preview.textContent).toContain("8.8.8.8 → ip");
    // The 'other' classification is surfaced, not hidden — it contributes no
    // hypothesis server-side, so the analyst must be able to see that.
    expect(preview.textContent).toContain("nonsense-value → other");
  });

  it("combines IOCs with adversaries and TTPs in one request", async () => {
    renderPage();
    fireEvent.change(screen.getByTestId("plan-adversaries-input"), {
      target: { value: "APT29" },
    });
    fireEvent.change(screen.getByTestId("plan-ttps-input"), {
      target: { value: "T1059.001" },
    });
    fireEvent.change(screen.getByTestId("plan-iocs-input"), {
      target: { value: "evil.example.com" },
    });
    fireEvent.click(screen.getByTestId("generate-plan"));

    await waitFor(() =>
      expect(generateHuntPlan).toHaveBeenCalledWith({
        adversaries: ["APT29"],
        ttps: ["T1059.001"],
        iocs: [{ type: "domain", value: "evil.example.com" }],
      }),
    );
  });

  it("hides the preview when the field is empty", () => {
    renderPage();
    expect(screen.queryByTestId("plan-iocs-preview")).toBeNull();
  });
});
