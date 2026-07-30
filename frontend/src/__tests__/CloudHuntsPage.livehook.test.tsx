/**
 * CloudHuntsPage live-refresh wiring (#117 — the WS upgrade every other hunt
 * page got in the #116/#120 Phase C pass).
 *
 * The page used to run a bare 30 s ``setInterval``; it now goes through the
 * shared ``useLiveEventRefresh`` hook. These tests pin the wiring, not the
 * hook internals (``useLiveEventRefresh.test.tsx`` owns those):
 *  1. the hook is registered with HUNT_FINDING_* events and the 30 s net;
 *  2. the registered refetch really refreshes the findings feed.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";

// Capture hook registrations so the test can inspect args + drive the refetch.
const mockLiveRefresh = vi.fn();
vi.mock("@/hooks/useLiveEventRefresh", () => ({
  useLiveEventRefresh: (...a: unknown[]) => mockLiveRefresh(...a),
}));

let mockRole = "senior_analyst";
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel: (s: { user: { role: string } | null }) => unknown) =>
    sel({ user: { role: mockRole } }),
}));

// The page destructures the whole store hook; the builders it also imports
// from the module must stay real, so extend the original instead of
// replacing it wholesale.
const mockFetchFindings = vi.fn().mockResolvedValue(undefined);
vi.mock("@/stores/cloudStore", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/stores/cloudStore")>()),
  useCloudStore: () => ({
    findings: [],
    total: 0,
    page: 1,
    pageSize: 50,
    activeTab: "timeline",
    isLoading: false,
    isMutating: false,
    error: null,
    fetchFindings: mockFetchFindings,
    setTab: vi.fn(),
    setPage: vi.fn(),
    promote: vi.fn(),
    clearError: vi.fn(),
  }),
}));

import { CloudHuntsPage } from "@/components/cloud/CloudHuntsPage";
import { HUNT_FINDING_EVENTS } from "@/components/hunt/HuntTriagePage";

function renderPage() {
  return render(
    <MemoryRouter>
      <CloudHuntsPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRole = "senior_analyst";
});

describe("CloudHuntsPage live refresh", () => {
  it("registers the shared hook with HUNT_FINDING_* events and the 30 s net", () => {
    renderPage();
    expect(screen.getByTestId("cloud-hunts-page")).toBeInTheDocument();

    expect(mockLiveRefresh).toHaveBeenCalled();
    const [, eventTypes, options] = mockLiveRefresh.mock.calls[0] as [
      () => void,
      readonly string[],
      { pollIntervalMs?: number },
    ];
    expect(eventTypes).toEqual(HUNT_FINDING_EVENTS);
    expect(options?.pollIntervalMs).toBe(30_000);
  });

  it("the registered refetch refreshes the findings feed", () => {
    renderPage();
    // Initial load happens once on mount…
    expect(mockFetchFindings).toHaveBeenCalledTimes(1);

    // …and the callback handed to the hook triggers a fresh fetch, which is
    // what a HUNT_FINDING_* WS event (or the polling net) will invoke.
    const [refetch] = mockLiveRefresh.mock.calls[0] as [() => void];
    refetch();
    expect(mockFetchFindings).toHaveBeenCalledTimes(2);
  });
});
