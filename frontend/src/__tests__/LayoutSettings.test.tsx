/**
 * PunchList view-settings dropdown (#108 role-tuned views): toggling the
 * handover section and changing the default filter persist via
 * putDashboardLayout; Reset calls resetDashboardLayout and is only enabled
 * once a customization exists; the source badge reflects user vs role default.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const putDashboardLayout = vi.fn();
const resetDashboardLayout = vi.fn();

vi.mock("@/api/dashboard", () => ({
  putDashboardLayout: (...a: unknown[]) => putDashboardLayout(...a),
  resetDashboardLayout: (...a: unknown[]) => resetDashboardLayout(...a),
}));

import { LayoutSettings } from "@/components/investigations/LayoutSettings";
import type { DashboardLayout } from "@/types/dashboard";

const STATUS_OPTIONS = [
  { label: "All", value: "" },
  { label: "Investigating", value: "investigating" },
  { label: "Failed", value: "failed" },
];

const STOCK: DashboardLayout = {
  sections: ["handover", "investigations"],
  default_status_filter: "",
};

function renderSettings(
  overrides: Partial<{ layout: DashboardLayout; source: string }> = {},
) {
  const onApplied = vi.fn();
  render(
    <LayoutSettings
      layout={overrides.layout ?? STOCK}
      source={overrides.source ?? "role_default"}
      statusOptions={STATUS_OPTIONS}
      onApplied={onApplied}
    />,
  );
  fireEvent.click(screen.getByTestId("layout-settings-button"));
  return { onApplied };
}

describe("LayoutSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows the source badge for a role default and disables reset", () => {
    renderSettings();
    expect(screen.getByTestId("layout-settings-source").textContent).toBe(
      "Role default",
    );
    expect(
      (screen.getByTestId("layout-settings-reset-button") as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it("unchecking the handover toggle saves the layout without the section", async () => {
    const saved = {
      layout: { sections: ["investigations"], default_status_filter: "" },
      source: "user",
      role: "analyst",
    };
    putDashboardLayout.mockResolvedValue(saved);
    const { onApplied } = renderSettings();

    fireEvent.click(screen.getByTestId("layout-settings-handover-toggle"));
    await waitFor(() =>
      expect(putDashboardLayout).toHaveBeenCalledWith({
        sections: ["investigations"],
        default_status_filter: "",
      }),
    );
    await waitFor(() => expect(onApplied).toHaveBeenCalledWith(saved));
  });

  it("changing the default filter saves it", async () => {
    const saved = {
      layout: { sections: ["handover", "investigations"], default_status_filter: "investigating" },
      source: "user",
      role: "analyst",
    };
    putDashboardLayout.mockResolvedValue(saved);
    const { onApplied } = renderSettings();

    fireEvent.change(screen.getByTestId("layout-settings-filter-select"), {
      target: { value: "investigating" },
    });
    await waitFor(() =>
      expect(putDashboardLayout).toHaveBeenCalledWith({
        sections: ["handover", "investigations"],
        default_status_filter: "investigating",
      }),
    );
    await waitFor(() => expect(onApplied).toHaveBeenCalledWith(saved));
  });

  it("reset calls the API and reports the role default back", async () => {
    const roleDefault = {
      layout: STOCK,
      source: "role_default",
      role: "analyst",
    };
    resetDashboardLayout.mockResolvedValue(roleDefault);
    const { onApplied } = renderSettings({
      layout: { sections: ["investigations"], default_status_filter: "failed" },
      source: "user",
    });

    expect(screen.getByTestId("layout-settings-source").textContent).toBe(
      "Customized",
    );
    fireEvent.click(screen.getByTestId("layout-settings-reset-button"));
    await waitFor(() => expect(resetDashboardLayout).toHaveBeenCalled());
    await waitFor(() => expect(onApplied).toHaveBeenCalledWith(roleDefault));
  });

  it("a failed save leaves the parent untouched", async () => {
    putDashboardLayout.mockRejectedValue(new Error("boom"));
    const { onApplied } = renderSettings();

    fireEvent.click(screen.getByTestId("layout-settings-handover-toggle"));
    await waitFor(() => expect(putDashboardLayout).toHaveBeenCalled());
    expect(onApplied).not.toHaveBeenCalled();
  });
});
