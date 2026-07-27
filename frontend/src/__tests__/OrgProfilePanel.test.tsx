/**
 * Organisation-profile editor (#418 / GH #393): the panel hydrates the loaded
 * profile into its fields, a save PUTs the WHOLE profile (parsing the
 * line-oriented tech-stack / shift editors back to structured JSON and
 * preserving fields the editor doesn't surface), non-admins get a read-only
 * view, and a failed fetch hides the panel.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const getOrgProfile = vi.fn();
const updateOrgProfile = vi.fn();
let mockRole = "admin";

vi.mock("@/api/orgProfile", () => ({
  getOrgProfile: (...a: unknown[]) => getOrgProfile(...a),
  updateOrgProfile: (...a: unknown[]) => updateOrgProfile(...a),
  emptyOrgProfile: () => ({
    industry: "",
    compliance: [],
    tech_stack: {},
    critical_assets: [],
    ir_team: { shifts: [], escalation_paths: [], on_call: {} },
  }),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { role: mockRole } }),
}));

import { OrgProfilePanel } from "@/components/settings/OrgProfilePanel";

const PROFILE = {
  industry: "financial_services",
  compliance: ["PCI-DSS", "SOX"],
  tech_stack: { siem: ["Splunk"], edr: ["CrowdStrike"] },
  critical_assets: [{ name: "core-db", type: "database" }],
  ir_team: {
    shifts: [{ name: "Day", timezone: "UTC", hours: "08-16" }],
    escalation_paths: [{ tier: 1 }],
    on_call: { name: "Alice" },
  },
};

describe("OrgProfilePanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "admin";
    getOrgProfile.mockResolvedValue({ profile: structuredClone(PROFILE) });
    updateOrgProfile.mockImplementation((p: unknown) => Promise.resolve({ profile: p }));
  });

  it("hydrates fields and saves the full profile, preserving unsurfaced fields", async () => {
    render(<OrgProfilePanel />);
    const industry = (await screen.findByTestId("org-profile-industry")) as HTMLInputElement;
    expect(industry.value).toBe("financial_services");
    expect((screen.getByTestId("org-profile-compliance") as HTMLInputElement).value).toBe(
      "PCI-DSS, SOX",
    );

    fireEvent.change(industry, { target: { value: "healthcare" } });
    fireEvent.change(screen.getByTestId("org-profile-compliance"), {
      target: { value: "HIPAA, SOC2" },
    });
    fireEvent.click(screen.getByTestId("org-profile-save"));

    // The whole profile is sent: edited fields updated, structured editors
    // round-tripped back to JSON, and fields the editor doesn't surface
    // (critical_assets, escalation_paths, on_call) preserved intact.
    await waitFor(() =>
      expect(updateOrgProfile).toHaveBeenCalledWith({
        industry: "healthcare",
        compliance: ["HIPAA", "SOC2"],
        tech_stack: { siem: ["Splunk"], edr: ["CrowdStrike"] },
        critical_assets: [{ name: "core-db", type: "database" }],
        ir_team: {
          shifts: [{ name: "Day", timezone: "UTC", hours: "08-16" }],
          escalation_paths: [{ tier: 1 }],
          on_call: { name: "Alice" },
        },
      }),
    );
  });

  it("non-admins get a read-only view with no editor controls", async () => {
    mockRole = "analyst";
    render(<OrgProfilePanel />);
    await screen.findByTestId("org-profile-readonly");
    expect(screen.getByTestId("org-profile-view-industry").textContent).toBe("financial_services");
    expect(screen.getByTestId("org-profile-view-compliance").textContent).toBe("PCI-DSS, SOX");
    expect(screen.queryByTestId("org-profile-industry")).toBeNull();
    expect(screen.queryByTestId("org-profile-save")).toBeNull();
  });

  it("hides itself when the fetch fails", async () => {
    getOrgProfile.mockRejectedValue(new Error("boom"));
    render(<OrgProfilePanel />);
    await waitFor(() => expect(getOrgProfile).toHaveBeenCalled());
    expect(screen.queryByTestId("org-profile-panel")).toBeNull();
  });
});
