/**
 * Autonomy editor panel (#418 slice 8): admin level-selects send the FULL
 * overrides dict (wholesale-replace PUT), choosing "default" removes the
 * override, reset sends {}, containment categories render locked with no
 * select, and non-admins get the read-only chip view.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const getAutonomyConfig = vi.fn();
const putAutonomyOverrides = vi.fn();
let mockRole = "admin";

vi.mock("@/api/configSchema", () => ({
  getAutonomyConfig: (...a: unknown[]) => getAutonomyConfig(...a),
  putAutonomyOverrides: (...a: unknown[]) => putAutonomyOverrides(...a),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { role: mockRole } }),
}));

import { AutonomyPanel } from "@/components/settings/AutonomyPanel";

const CONFIG = {
  categories: [
    { key: "siem_query", level: "L3", hitl_forced: false, overridden: false },
    { key: "playbook_execution", level: "L0", hitl_forced: false, overridden: true },
    { key: "host_isolation", level: "L0", hitl_forced: true, overridden: false },
  ],
  levels: { L0: "Every action requires approval", L3: "Agent runs independently" },
  editable: true,
};

describe("AutonomyPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "admin";
    getAutonomyConfig.mockResolvedValue(structuredClone(CONFIG));
    putAutonomyOverrides.mockImplementation(() =>
      Promise.resolve(structuredClone(CONFIG)),
    );
  });

  it("changing a level sends the FULL overrides dict", async () => {
    render(<AutonomyPanel />);
    fireEvent.change(await screen.findByTestId("autonomy-select-siem_query"), {
      target: { value: "L1" },
    });
    await waitFor(() =>
      expect(putAutonomyOverrides).toHaveBeenCalledWith({
        playbook_execution: "L0",
        siem_query: "L1",
      }),
    );
  });

  it("choosing default removes the category from the dict", async () => {
    render(<AutonomyPanel />);
    fireEvent.change(
      await screen.findByTestId("autonomy-select-playbook_execution"),
      { target: { value: "" } },
    );
    await waitFor(() => expect(putAutonomyOverrides).toHaveBeenCalledWith({}));
  });

  it("reset sends an empty overrides dict", async () => {
    render(<AutonomyPanel />);
    fireEvent.click(await screen.findByTestId("autonomy-reset-button"));
    await waitFor(() => expect(putAutonomyOverrides).toHaveBeenCalledWith({}));
  });

  it("containment renders locked with no select", async () => {
    render(<AutonomyPanel />);
    await screen.findByTestId("autonomy-category-host_isolation");
    expect(screen.getByTestId("autonomy-hitl-lock-host_isolation")).toBeTruthy();
    expect(screen.queryByTestId("autonomy-select-host_isolation")).toBeNull();
  });

  it("non-admins see read-only chips with no controls", async () => {
    mockRole = "analyst";
    render(<AutonomyPanel />);
    await screen.findByTestId("autonomy-category-siem_query");
    expect(screen.queryByTestId("autonomy-select-siem_query")).toBeNull();
    expect(screen.queryByTestId("autonomy-reset-button")).toBeNull();
  });

  it("hides itself when the fetch fails", async () => {
    getAutonomyConfig.mockRejectedValue(new Error("boom"));
    render(<AutonomyPanel />);
    await waitFor(() => expect(getAutonomyConfig).toHaveBeenCalled());
    expect(screen.queryByTestId("config-center-autonomy")).toBeNull();
  });
});
