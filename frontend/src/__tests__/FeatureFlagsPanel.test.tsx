/**
 * Feature-flag toggle panel (#418 slice 5): admins flip/add/remove flags with
 * every write sending the FULL dict (wholesale-replace PUT), client-side key
 * validation blocks bad names before any request, and non-admins get a
 * read-only view with no controls.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const getFeatureFlags = vi.fn();
const putFeatureFlags = vi.fn();
let mockRole = "admin";

vi.mock("@/api/configSchema", () => ({
  getFeatureFlags: (...a: unknown[]) => getFeatureFlags(...a),
  putFeatureFlags: (...a: unknown[]) => putFeatureFlags(...a),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) =>
    selector({ user: { role: mockRole } }),
}));

import { FeatureFlagsPanel } from "@/components/settings/FeatureFlagsPanel";

const FLAGS = { beta_search: true, dark_launch: false };

describe("FeatureFlagsPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "admin";
    getFeatureFlags.mockResolvedValue({ flags: { ...FLAGS } });
    putFeatureFlags.mockImplementation((flags: Record<string, boolean>) =>
      Promise.resolve({ flags }),
    );
  });

  it("toggling sends the FULL updated dict", async () => {
    render(<FeatureFlagsPanel />);
    fireEvent.click(await screen.findByTestId("feature-flag-toggle-dark_launch"));
    await waitFor(() =>
      expect(putFeatureFlags).toHaveBeenCalledWith({
        beta_search: true,
        dark_launch: true,
      }),
    );
  });

  it("removing a flag sends the dict without it", async () => {
    render(<FeatureFlagsPanel />);
    fireEvent.click(await screen.findByTestId("feature-flag-remove-beta_search"));
    await waitFor(() =>
      expect(putFeatureFlags).toHaveBeenCalledWith({ dark_launch: false }),
    );
  });

  it("adding a flag validates the key client-side first", async () => {
    render(<FeatureFlagsPanel />);
    await screen.findByTestId("feature-flags-list");

    fireEvent.change(screen.getByTestId("feature-flags-add-input"), {
      target: { value: "Bad-Key" },
    });
    fireEvent.click(screen.getByTestId("feature-flags-add-button"));
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(putFeatureFlags).not.toHaveBeenCalled();

    fireEvent.change(screen.getByTestId("feature-flags-add-input"), {
      target: { value: "new_toggle" },
    });
    fireEvent.click(screen.getByTestId("feature-flags-add-button"));
    await waitFor(() =>
      expect(putFeatureFlags).toHaveBeenCalledWith({
        ...FLAGS,
        new_toggle: false,
      }),
    );
  });

  it("non-admins get a read-only view with no controls", async () => {
    mockRole = "analyst";
    render(<FeatureFlagsPanel />);
    await screen.findByTestId("feature-flags-list");
    expect(screen.getByTestId("feature-flag-state-beta_search").textContent).toBe("on");
    expect(screen.queryByTestId("feature-flag-toggle-beta_search")).toBeNull();
    expect(screen.queryByTestId("feature-flags-add-input")).toBeNull();
  });

  it("hides itself when the fetch fails", async () => {
    getFeatureFlags.mockRejectedValue(new Error("boom"));
    render(<FeatureFlagsPanel />);
    await waitFor(() => expect(getFeatureFlags).toHaveBeenCalled());
    expect(screen.queryByTestId("feature-flags-panel")).toBeNull();
  });
});
