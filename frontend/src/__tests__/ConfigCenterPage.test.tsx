/**
 * Configuration Center (#418 slice 2): runtime surfaces render as cards with
 * scope badges and internal links, deploy-time entries render with sensitive
 * values redacted, the name filter narrows the env table, and a failed fetch
 * shows the error state.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const getConfigSchema = vi.fn();

vi.mock("@/api/configSchema", () => ({
  getConfigSchema: (...a: unknown[]) => getConfigSchema(...a),
}));

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { ConfigCenterPage } from "@/components/settings/ConfigCenterPage";

const SCHEMA = {
  runtime: [
    {
      key: "org_profile",
      title: "Organization Profile",
      description: "Industry, compliance frameworks…",
      scope: "org",
      write_permission: "config:org_profile",
      api: "/api/v1/config/org-profile",
      ui: "/settings",
    },
    {
      key: "autonomy",
      title: "Autonomy & HITL Gates",
      description: "Per-category autonomy levels.",
      scope: "org",
      write_permission: "config:edit",
      api: null,
      ui: null,
    },
  ],
  deploy_time: [
    {
      field: "env",
      env: "BTAGENT_ENV",
      type: "str",
      sensitive: false,
      value: "test",
      is_default: false,
    },
    {
      field: "jwt_secret",
      env: "BTAGENT_JWT_SECRET",
      type: "str",
      sensitive: true,
      value: null,
      is_default: false,
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <ConfigCenterPage />
    </MemoryRouter>,
  );
}

describe("ConfigCenterPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getConfigSchema.mockResolvedValue(SCHEMA);
  });

  it("renders runtime surfaces with scope badge and link, and the no-editor gap", async () => {
    renderPage();
    const card = await screen.findByTestId("config-surface-org_profile");
    expect(card.textContent).toContain("Organization Profile");
    expect(
      screen.getByTestId("config-surface-org_profile-scope").textContent,
    ).toBe("org");
    expect(
      screen.getByTestId("config-surface-org_profile-link").getAttribute("href"),
    ).toBe("/settings");

    const autonomy = screen.getByTestId("config-surface-autonomy");
    expect(autonomy.textContent).toContain("no runtime editor yet");
    expect(screen.queryByTestId("config-surface-autonomy-link")).toBeNull();
  });

  it("redacts sensitive deploy-time values and shows plain ones", async () => {
    renderPage();
    await screen.findByTestId("config-center-env-table");
    expect(screen.getByTestId("config-env-env").textContent).toContain("test");
    expect(screen.getByTestId("config-env-jwt_secret-redacted")).toBeTruthy();
    expect(screen.getByTestId("config-env-jwt_secret").textContent).not.toContain(
      "null",
    );
  });

  it("filters the env table by name", async () => {
    renderPage();
    await screen.findByTestId("config-center-env-table");
    fireEvent.change(screen.getByTestId("config-center-env-filter"), {
      target: { value: "jwt" },
    });
    expect(screen.queryByTestId("config-env-env")).toBeNull();
    expect(screen.getByTestId("config-env-jwt_secret")).toBeTruthy();

    fireEvent.change(screen.getByTestId("config-center-env-filter"), {
      target: { value: "zzz-no-match" },
    });
    expect(screen.getByTestId("config-center-env-empty")).toBeTruthy();
  });

  it("shows the error state when the fetch fails", async () => {
    getConfigSchema.mockRejectedValue(new Error("boom"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByTestId("config-center-error")).toBeTruthy(),
    );
  });
});
