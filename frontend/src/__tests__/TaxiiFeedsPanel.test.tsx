/**
 * TaxiiFeedsPanel (#105 UC-2.1) — the admin screen for the backend feed store.
 *
 * What carries weight: the panel self-effaces below taxii:view, management
 * affordances exist only for admins, the raw-credential 422 comes through
 * verbatim (the server's security refusal must teach, not vanish), and a
 * failing feed's error is visible rather than mysterious.
 */
import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const listTaxiiFeeds = vi.fn();
const createTaxiiFeed = vi.fn();
const updateTaxiiFeed = vi.fn();
const deleteTaxiiFeed = vi.fn();

vi.mock("@/api/taxii", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/taxii")>()),
  listTaxiiFeeds: (...a: unknown[]) => listTaxiiFeeds(...a),
  createTaxiiFeed: (...a: unknown[]) => createTaxiiFeed(...a),
  updateTaxiiFeed: (...a: unknown[]) => updateTaxiiFeed(...a),
  deleteTaxiiFeed: (...a: unknown[]) => deleteTaxiiFeed(...a),
}));

const mockRole = vi.fn();
vi.mock("@/stores/authStore", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/stores/authStore")>()),
  useAuthStore: (selector: (s: { user: { role: string } }) => unknown) =>
    selector({ user: { role: mockRole() } }),
}));

import { TaxiiFeedsPanel } from "@/components/connectors/TaxiiFeedsPanel";
import { ApiError } from "@/api/client";

function feed(over: Record<string, unknown> = {}) {
  return {
    id: "feed_1",
    name: "CISA AIS",
    server_url: "https://taxii.example.gov/api1/",
    collection_id: "col-1",
    auth_style: "bearer",
    auth_secret_ref: "${secret:vault:cti/taxii}",
    poll_interval_minutes: 60,
    enabled: true,
    last_cursor: null,
    last_polled_at: "2026-07-29T10:00:00Z",
    last_status: "ok",
    last_error: "",
    objects_ingested: 42,
    intake_investigation_id: null,
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-07-29T10:00:00Z",
    ...over,
  };
}

describe("TaxiiFeedsPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listTaxiiFeeds.mockResolvedValue({ items: [feed()], total: 1 });
  });

  it("self-effaces below senior analyst", () => {
    mockRole.mockReturnValue("analyst");
    render(<TaxiiFeedsPanel />);
    expect(screen.queryByTestId("taxii-feeds-panel")).not.toBeInTheDocument();
    expect(listTaxiiFeeds).not.toHaveBeenCalled();
  });

  it("senior analyst sees feeds and telemetry but no management controls", async () => {
    mockRole.mockReturnValue("senior_analyst");
    render(<TaxiiFeedsPanel />);
    expect(await screen.findByTestId("taxii-feeds-list")).toBeInTheDocument();
    expect(screen.getByText("CISA AIS")).toBeInTheDocument();
    expect(screen.getByText(/42 objects/)).toBeInTheDocument();
    expect(screen.queryByTestId("taxii-feed-form")).not.toBeInTheDocument();
    expect(screen.queryByTestId("taxii-feed-toggle-feed_1")).not.toBeInTheDocument();
  });

  it("F10: incident commander outranks senior analyst and sees the panel", async () => {
    // taxii:view is senior_analyst+; incident_commander is above it in the
    // RBAC hierarchy, so the panel must render (an equality gate hid it).
    mockRole.mockReturnValue("incident_commander");
    render(<TaxiiFeedsPanel />);
    expect(await screen.findByTestId("taxii-feeds-list")).toBeInTheDocument();
    // Still no admin-only management controls.
    expect(screen.queryByTestId("taxii-feed-form")).not.toBeInTheDocument();
  });

  it("admin creates a feed with a secret reference", async () => {
    mockRole.mockReturnValue("admin");
    createTaxiiFeed.mockResolvedValue(feed({ id: "feed_2" }));
    render(<TaxiiFeedsPanel />);
    await screen.findByTestId("taxii-feed-form");

    fireEvent.change(screen.getByTestId("taxii-feed-name"), { target: { value: "ISAC" } });
    fireEvent.change(screen.getByTestId("taxii-feed-url"), {
      target: { value: "https://taxii.isac.example/api2/" },
    });
    fireEvent.change(screen.getByTestId("taxii-feed-collection"), {
      target: { value: "col-9" },
    });
    fireEvent.change(screen.getByTestId("taxii-feed-secret-ref"), {
      target: { value: "${env:ISAC_TOKEN}" },
    });
    fireEvent.click(screen.getByTestId("taxii-feed-create"));

    await waitFor(() => expect(createTaxiiFeed).toHaveBeenCalled());
    expect(createTaxiiFeed).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "ISAC",
        server_url: "https://taxii.isac.example/api2/",
        collection_id: "col-9",
        auth_secret_ref: "${env:ISAC_TOKEN}",
      }),
    );
  });

  it("surfaces the raw-credential 422 verbatim", async () => {
    mockRole.mockReturnValue("admin");
    createTaxiiFeed.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail:
          "auth_secret_ref must be a single ${secret:...} or ${env:...} reference; raw credential material is not accepted.",
      }),
    );
    render(<TaxiiFeedsPanel />);
    await screen.findByTestId("taxii-feed-form");
    fireEvent.change(screen.getByTestId("taxii-feed-name"), { target: { value: "Bad" } });
    fireEvent.change(screen.getByTestId("taxii-feed-url"), {
      target: { value: "https://x.example/" },
    });
    fireEvent.change(screen.getByTestId("taxii-feed-collection"), {
      target: { value: "c" },
    });
    fireEvent.click(screen.getByTestId("taxii-feed-create"));
    expect(await screen.findByTestId("taxii-feeds-error")).toHaveTextContent(
      /raw credential material is not accepted/,
    );
  });

  it("admin toggles a feed and delete requires a second confirming click", async () => {
    mockRole.mockReturnValue("admin");
    updateTaxiiFeed.mockResolvedValue(feed({ enabled: false }));
    deleteTaxiiFeed.mockResolvedValue(undefined);
    render(<TaxiiFeedsPanel />);
    await screen.findByTestId("taxii-feeds-list");

    fireEvent.click(screen.getByTestId("taxii-feed-toggle-feed_1"));
    await waitFor(() =>
      expect(updateTaxiiFeed).toHaveBeenCalledWith("feed_1", { enabled: false }),
    );

    fireEvent.click(screen.getByTestId("taxii-feed-delete-feed_1"));
    expect(deleteTaxiiFeed).not.toHaveBeenCalled(); // first click only arms
    expect(screen.getByTestId("taxii-feed-delete-feed_1")).toHaveTextContent(
      /Confirm delete/,
    );
    fireEvent.click(screen.getByTestId("taxii-feed-delete-feed_1"));
    await waitFor(() => expect(deleteTaxiiFeed).toHaveBeenCalledWith("feed_1"));
  });

  it("shows a failing feed's last error", async () => {
    mockRole.mockReturnValue("senior_analyst");
    listTaxiiFeeds.mockResolvedValue({
      items: [feed({ last_status: "error", last_error: "401 from api-root" })],
      total: 1,
    });
    render(<TaxiiFeedsPanel />);
    expect(await screen.findByTestId("taxii-feed-error")).toHaveTextContent(
      /401 from api-root/,
    );
  });
});
