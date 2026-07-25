/**
 * Cross-case notebook search panel (#108 UC-5.2): submitting queries the
 * notebook route with q + optional disposition, results render with a
 * case deep link, the empty state distinguishes "no matches", and a failed
 * search shows the error instead of stale results.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const searchNotebook = vi.fn();

vi.mock("@/api/iocs", () => ({
  searchNotebook: (...a: unknown[]) => searchNotebook(...a),
}));

import { NotebookSearchPanel } from "@/components/iocs/NotebookSearchPanel";

const HIT = {
  id: "ioc_hit1",
  type: "domain",
  value: "beacon.example.com",
  source: "test",
  confidence: 0.8,
  first_seen: "2026-07-24T00:00:00Z",
  investigation_id: "inv_case_a",
  pinned: true,
  tags: ["apt29"],
  analyst_note: "Cobalt Strike staging domain",
  disposition: "under_review",
};

function openPanel() {
  render(
    <MemoryRouter>
      <NotebookSearchPanel />
    </MemoryRouter>,
  );
  fireEvent.click(screen.getByTestId("notebook-search-toggle"));
}

describe("NotebookSearchPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    searchNotebook.mockResolvedValue({ items: [HIT], total: 1, page: 1, page_size: 25 });
  });

  it("searches with q and renders hits with a case link", async () => {
    openPanel();
    fireEvent.change(screen.getByTestId("notebook-search-input"), {
      target: { value: "cobalt" },
    });
    fireEvent.click(screen.getByTestId("notebook-search-button"));

    await waitFor(() =>
      expect(searchNotebook).toHaveBeenCalledWith("cobalt", undefined),
    );
    const row = await screen.findByTestId("notebook-search-result-ioc_hit1");
    expect(row.textContent).toContain("beacon.example.com");
    expect(row.textContent).toContain("Cobalt Strike staging domain");
    expect(
      screen
        .getByTestId("notebook-search-case-link-ioc_hit1")
        .getAttribute("href"),
    ).toBe("/investigations/inv_case_a");
  });

  it("passes the selected disposition through", async () => {
    openPanel();
    fireEvent.change(screen.getByTestId("notebook-search-disposition-select"), {
      target: { value: "confirmed_malicious" },
    });
    fireEvent.click(screen.getByTestId("notebook-search-button"));

    await waitFor(() =>
      expect(searchNotebook).toHaveBeenCalledWith("", "confirmed_malicious"),
    );
  });

  it("shows the empty state on zero matches", async () => {
    searchNotebook.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 25 });
    openPanel();
    fireEvent.click(screen.getByTestId("notebook-search-button"));
    expect(await screen.findByTestId("notebook-search-empty")).toBeTruthy();
  });

  it("shows an error and no results when the search fails", async () => {
    searchNotebook.mockRejectedValue(new Error("boom"));
    openPanel();
    fireEvent.click(screen.getByTestId("notebook-search-button"));

    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByTestId("notebook-search-results")).toBeNull();
  });
});
