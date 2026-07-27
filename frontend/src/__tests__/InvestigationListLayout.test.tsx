/**
 * Role-tuned PunchList views (#108): the dashboard-layout preference must
 * preselect the status pill and drive HandoverCard visibility — but never
 * clobber a pill the user already clicked, and never break the page when the
 * preference fetch fails.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router";

const getDashboardLayout = vi.fn();
const fetchInvestigations = vi.fn();

vi.mock("@/api/dashboard", () => ({
  getDashboardLayout: (...a: unknown[]) => getDashboardLayout(...a),
}));

vi.mock("@/stores/investigationStore", () => ({
  useInvestigationStore: () => ({
    investigations: [],
    isLoading: false,
    error: null,
    fetchInvestigations,
  }),
}));

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

vi.mock("@/components/investigations/HandoverCard", () => ({
  HandoverCard: () => <div data-testid="handover-card-stub" />,
}));

vi.mock("@/components/investigations/NewInvestigationModal", () => ({
  NewInvestigationModal: () => null,
}));

import { InvestigationList } from "@/components/investigations/InvestigationList";

function layoutResponse(
  sections: string[],
  defaultStatusFilter: string,
  source = "role_default",
) {
  return {
    layout: { sections, default_status_filter: defaultStatusFilter },
    source,
    role: "analyst",
  };
}

function renderList() {
  return render(
    <MemoryRouter>
      <InvestigationList />
    </MemoryRouter>,
  );
}

describe("InvestigationList dashboard-layout preference", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getDashboardLayout.mockResolvedValue(
      layoutResponse(["handover", "investigations"], ""),
    );
  });

  it("preselects the preferred status pill and fetches with it", async () => {
    getDashboardLayout.mockResolvedValue(
      layoutResponse(["handover", "investigations"], "running"),
    );
    renderList();

    const pill = await screen.findByTestId("investigation-list-filter-running");
    await waitFor(() => expect(pill.getAttribute("aria-selected")).toBe("true"));
    await waitFor(() =>
      expect(fetchInvestigations).toHaveBeenCalledWith(
        expect.objectContaining({ status: "running" }),
      ),
    );
  });

  it("ignores a preferred filter the pill row doesn't know", async () => {
    getDashboardLayout.mockResolvedValue(
      layoutResponse(["handover", "investigations"], "investigating"),
    );
    renderList();
    await waitFor(() => expect(getDashboardLayout).toHaveBeenCalled());
    expect(
      screen.getByTestId("investigation-list-filter-all").getAttribute("aria-selected"),
    ).toBe("true");
  });

  it("does not clobber a pill the user clicked before the fetch resolved", async () => {
    let resolveLayout: (v: unknown) => void = () => {};
    getDashboardLayout.mockReturnValue(
      new Promise((resolve) => {
        resolveLayout = resolve;
      }),
    );
    renderList();

    fireEvent.click(screen.getByTestId("investigation-list-filter-failed"));
    resolveLayout(layoutResponse(["handover", "investigations"], "running"));

    await waitFor(() =>
      expect(
        screen.getByTestId("investigation-list-filter-failed").getAttribute("aria-selected"),
      ).toBe("true"),
    );
    expect(
      screen.getByTestId("investigation-list-filter-running").getAttribute("aria-selected"),
    ).toBe("false");
  });

  it("hides the handover card when the layout omits the section", async () => {
    getDashboardLayout.mockResolvedValue(layoutResponse(["investigations"], ""));
    renderList();
    await waitFor(() => expect(getDashboardLayout).toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.queryByTestId("handover-card-stub")).toBeNull(),
    );
  });

  it("keeps the stock layout when the preference fetch fails", async () => {
    getDashboardLayout.mockRejectedValue(new Error("boom"));
    renderList();
    await waitFor(() => expect(getDashboardLayout).toHaveBeenCalled());
    expect(screen.getByTestId("handover-card-stub")).toBeTruthy();
    expect(
      screen.getByTestId("investigation-list-filter-all").getAttribute("aria-selected"),
    ).toBe("true");
  });
});
