/**
 * UC-5.2 pinned-only filter wiring (#108): the checkbox must drive the store
 * filter as a tri-state — checked → pinned: true, unchecked → pinned:
 * undefined — so the server only ever sees ``pinned=true`` or no param
 * (``pinned=false`` would silently mean "unpinned only").
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const setFilters = vi.fn();
let mockFilters: Record<string, unknown> = {};

vi.mock("@/stores/iocStore", () => ({
  useIOCStore: () => ({
    iocs: [],
    isLoading: false,
    isEnriching: false,
    error: null,
    filters: mockFilters,
    sort: { field: "first_seen", direction: "desc" },
    total: 0,
    selectedIOCId: null,
    selectedIds: new Set(),
    fetchIOCs: vi.fn(),
    setFilters,
    setSort: vi.fn(),
    selectIOC: vi.fn(),
    toggleSelected: vi.fn(),
    selectAll: vi.fn(),
    clearSelection: vi.fn(),
    bulkEnrich: vi.fn(),
  }),
}));

vi.mock("@/stores/investigationStore", () => ({
  useInvestigationStore: () => ({
    investigations: [],
    fetchInvestigations: vi.fn(),
  }),
}));

vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { IOCNotebook } from "@/components/iocs/IOCNotebook";

describe("IOCNotebook pinned-only filter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFilters = {};
  });

  it("checking sets pinned: true", () => {
    render(
      <MemoryRouter>
        <IOCNotebook />
      </MemoryRouter>,
    );
    const box = screen.getByTestId("ioc-notebook-pinned-filter-input") as HTMLInputElement;
    expect(box.checked).toBe(false);

    fireEvent.click(box);
    expect(setFilters).toHaveBeenCalledWith({ pinned: true });
  });

  it("unchecking clears to undefined (never pinned: false)", () => {
    mockFilters = { pinned: true };
    render(
      <MemoryRouter>
        <IOCNotebook />
      </MemoryRouter>,
    );
    const box = screen.getByTestId("ioc-notebook-pinned-filter-input") as HTMLInputElement;
    expect(box.checked).toBe(true);

    fireEvent.click(box);
    expect(setFilters).toHaveBeenCalledWith({ pinned: undefined });
    expect(setFilters).not.toHaveBeenCalledWith({ pinned: false });
  });
});
