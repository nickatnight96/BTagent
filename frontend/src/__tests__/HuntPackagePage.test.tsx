/**
 * RTL tests for the HuntPackagePage package-history panel (#99):
 *  1. History renders stored summaries (label, counts, techniques) after fetch.
 *  2. Clicking an entry re-opens the package via GET /hunts/packages/{id}.
 *  3. Generating a package refreshes the history list.
 *  4. Empty history renders no panel.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// ---- API mocks ----

const mockGenerate = vi.fn();
const mockList = vi.fn();
const mockGet = vi.fn();

vi.mock("@/api/hunts", () => ({
  generateHuntPackage: (...a: unknown[]) => mockGenerate(...a),
  listHuntPackages: (...a: unknown[]) => mockList(...a),
  getHuntPackage: (...a: unknown[]) => mockGet(...a),
}));

// Header pulls in auth/UI stores + the notification bell — irrelevant here.
vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { HuntPackagePage } from "@/components/hunts/HuntPackagePage";

// --------------------------------------------------------------------------- //
// Fixtures
// --------------------------------------------------------------------------- //

const SUMMARY_A = {
  id: "hpkg_A",
  source_label: "AA26-001",
  extracted_ioc_count: 5,
  deduped_count: 5,
  techniques: ["T1071", "T1105", "T1566", "T1059"],
  mock_mode: true,
  created_by: "usr_1",
  created_at: "2026-07-22T10:00:00Z",
};

const SUMMARY_B = {
  id: "hpkg_B",
  source_label: "vendor-report-42",
  extracted_ioc_count: 2,
  deduped_count: 2,
  techniques: ["T1190"],
  mock_mode: true,
  created_by: "usr_1",
  created_at: "2026-07-21T09:00:00Z",
};

const PACKAGE_A = {
  id: "hpkg_A",
  source_label: "AA26-001",
  extracted_ioc_count: 5,
  deduped_count: 5,
  derived_techniques: ["T1071", "T1105", "T1566", "T1059"],
  retro_report: {
    window_days: 90,
    iocs_checked: 5,
    sightings: [],
    sightings_by_tactic: {},
    techniques_with_sightings: [],
    coverage_gaps: [],
    compromise_suspected: false,
    generated_at: "2026-07-22T10:00:00Z",
    mock_mode: true,
  },
  queries: {},
  sigma_drafts: [],
  generated_at: "2026-07-22T10:00:00Z",
  mock_mode: true,
};

function renderPage() {
  return render(
    <MemoryRouter>
      <HuntPackagePage />
    </MemoryRouter>,
  );
}

async function openHistory() {
  const toggle = await screen.findByTestId("package-history-toggle");
  fireEvent.click(toggle);
}

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue({ items: [SUMMARY_A, SUMMARY_B], total: 2 });
  mockGet.mockResolvedValue(PACKAGE_A);
  mockGenerate.mockResolvedValue(PACKAGE_A);
});

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //

describe("HuntPackagePage package history", () => {
  it("renders stored summaries after the history fetch", async () => {
    renderPage();
    await openHistory();

    expect(screen.getByText("AA26-001")).toBeInTheDocument();
    expect(screen.getByText("vendor-report-42")).toBeInTheDocument();
    // 5 IOCs · 4 techniques · <relative time>
    expect(screen.getByText(/5 IOCs · 4 techniques/)).toBeInTheDocument();
    // Overflow indicator: 4 techniques, 3 badges + "+1"
    expect(screen.getByText("+1")).toBeInTheDocument();
    // Total in the header
    expect(screen.getByText("(2)")).toBeInTheDocument();
    expect(mockList).toHaveBeenCalledWith({ page_size: 20 });
  });

  it("re-opens a stored package on click via the detail endpoint", async () => {
    renderPage();
    await openHistory();

    fireEvent.click(screen.getByTestId("package-history-item-hpkg_A"));

    await waitFor(() => expect(mockGet).toHaveBeenCalledWith("hpkg_A"));
    // The re-opened package renders in the results section
    expect(await screen.findByTestId("hunt-package-result")).toBeInTheDocument();
    expect(
      screen.getByText(/No historical sightings — clean over the window/),
    ).toBeInTheDocument();
    // The open entry is marked
    expect(screen.getByText("(open)")).toBeInTheDocument();
  });

  it("refreshes history after generating a new package", async () => {
    renderPage();
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId("hunt-package-input"), {
      target: { value: "advisory text with 10.1.42.17" },
    });
    fireEvent.click(screen.getByText("Generate hunt package"));

    await waitFor(() => expect(mockGenerate).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(2));
  });

  it("renders no history panel when the store is empty", async () => {
    mockList.mockResolvedValue({ items: [], total: 0 });
    renderPage();

    await waitFor(() => expect(mockList).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId("package-history")).not.toBeInTheDocument();
  });
});
