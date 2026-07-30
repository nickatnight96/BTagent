import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";

const listTaxiiFeeds = vi.fn();
const createTaxiiFeed = vi.fn();
const updateTaxiiFeed = vi.fn();
const deleteTaxiiFeed = vi.fn();

vi.mock("@/api/taxii", () => ({
  listTaxiiFeeds: (...a: unknown[]) => listTaxiiFeeds(...a),
  createTaxiiFeed: (...a: unknown[]) => createTaxiiFeed(...a),
  updateTaxiiFeed: (...a: unknown[]) => updateTaxiiFeed(...a),
  deleteTaxiiFeed: (...a: unknown[]) => deleteTaxiiFeed(...a),
  MIN_POLL_INTERVAL_MINUTES: 5,
  MAX_POLL_INTERVAL_MINUTES: 10080,
}));

// Settable current role — the panel's read/write gating mirrors the API's
// taxii:view (senior_analyst+) / taxii:manage (admin) split.
let currentRole = "admin";
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel?: (s: Record<string, unknown>) => unknown) => {
    const state = { user: { id: "usr_t", username: "t", role: currentRole } };
    return sel ? sel(state) : state;
  },
}));

import { ApiError } from "@/api/client";
import { TaxiiFeedsPanel } from "@/components/connectors/TaxiiFeedsPanel";

const HEALTHY = {
  id: "taxii_ok1",
  name: "CISA AIS",
  server_url: "https://taxii.example.test/api1",
  collection_id: "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
  auth_style: "bearer" as const,
  auth_secret_ref: "${secret:vault:taxii/cisa#token}",
  poll_interval_minutes: 60,
  enabled: true,
  last_cursor: "2026-07-20T11:22:33.444Z",
  last_polled_at: "2026-07-20T11:25:00Z",
  last_status: "ok",
  last_error: "",
  objects_ingested: 1420,
  intake_investigation_id: "inv_intake1",
  created_at: "2026-07-01T00:00:00Z",
  updated_at: "2026-07-20T11:25:00Z",
};

const FAILING = {
  ...HEALTHY,
  id: "taxii_bad1",
  name: "Partner ISAC",
  auth_style: "none" as const,
  auth_secret_ref: "",
  enabled: false,
  last_cursor: null,
  last_polled_at: null,
  last_status: "error",
  last_error: "HTTP 401 from https://taxii.example.test/api1",
  objects_ingested: 0,
  intake_investigation_id: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  currentRole = "admin";
  listTaxiiFeeds.mockResolvedValue({ items: [HEALTHY, FAILING], total: 2 });
});

describe("TaxiiFeedsPanel", () => {
  it("lists feeds with their poll telemetry", async () => {
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-feed-row-taxii_ok1")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("taxii-status-taxii_ok1")).toHaveTextContent(
      "polled ok",
    );
    expect(screen.getByTestId("taxii-telemetry-taxii_ok1")).toHaveTextContent(
      "1,420",
    );
    // A feed the sweep is failing on must say so, and say why.
    expect(screen.getByTestId("taxii-status-taxii_bad1")).toHaveTextContent(
      "poll failed",
    );
    expect(screen.getByTestId("taxii-last-error-taxii_bad1")).toHaveTextContent(
      "HTTP 401",
    );
    expect(screen.getByTestId("taxii-enabled-taxii_bad1")).toHaveTextContent(
      "disabled",
    );
    // The reference is config and is echoed; nothing resolves it.
    expect(screen.getByTestId("taxii-secret-ref-taxii_ok1")).toHaveTextContent(
      "${secret:vault:taxii/cisa#token}",
    );
  });

  it("creates a feed, sending the reference and not raw material", async () => {
    createTaxiiFeed.mockResolvedValue({ ...HEALTHY, id: "taxii_new1" });
    render(<TaxiiFeedsPanel />);

    await waitFor(() => expect(screen.getByTestId("taxii-feed-add")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("taxii-feed-add"));

    fireEvent.change(screen.getByTestId("taxii-form-name-new"), {
      target: { value: "New feed" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-server-url-new"), {
      target: { value: "https://taxii.example.test/api1" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-collection-new"), {
      target: { value: "col-1" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-interval-new"), {
      target: { value: "30" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-auth-style-new"), {
      target: { value: "bearer" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-auth-ref-new"), {
      target: { value: "${env:TAXII_TOKEN}" },
    });
    fireEvent.click(screen.getByTestId("taxii-form-save-new"));

    await waitFor(() => expect(createTaxiiFeed).toHaveBeenCalledTimes(1));
    expect(createTaxiiFeed).toHaveBeenCalledWith({
      name: "New feed",
      server_url: "https://taxii.example.test/api1",
      collection_id: "col-1",
      auth_style: "bearer",
      auth_secret_ref: "${env:TAXII_TOKEN}",
      poll_interval_minutes: 30,
      enabled: true,
    });
    // The list is re-read so the new row (and its telemetry) shows up.
    await waitFor(() => expect(listTaxiiFeeds).toHaveBeenCalledTimes(2));
  });

  it("flags a raw token client-side and never sends it as a reference", async () => {
    render(<TaxiiFeedsPanel />);
    await waitFor(() => expect(screen.getByTestId("taxii-feed-add")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("taxii-feed-add"));

    fireEvent.change(screen.getByTestId("taxii-form-auth-style-new"), {
      target: { value: "bearer" },
    });
    fireEvent.change(screen.getByTestId("taxii-form-auth-ref-new"), {
      target: { value: "eyJhbGciOiJIUzI1NiJ9.raw-token" },
    });

    expect(screen.getByTestId("taxii-form-ref-invalid-new")).toBeInTheDocument();
    // The helper text is present whenever a reference is required.
    expect(screen.getByTestId("taxii-form-secret-hint-new")).toHaveTextContent(
      "never the token itself",
    );
  });

  it("surfaces the server's 422 detail verbatim instead of a generic message", async () => {
    createTaxiiFeed.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail:
          "auth_secret_ref must be a single ${secret:vault:...} / ${secret:aws:...} / ${env:VAR} reference",
      }),
    );
    render(<TaxiiFeedsPanel />);
    await waitFor(() => expect(screen.getByTestId("taxii-feed-add")).toBeInTheDocument());
    fireEvent.click(screen.getByTestId("taxii-feed-add"));

    fireEvent.change(screen.getByTestId("taxii-form-name-new"), {
      target: { value: "Bad feed" },
    });
    fireEvent.click(screen.getByTestId("taxii-form-save-new"));

    await waitFor(() =>
      expect(screen.getByTestId("taxii-form-error-new")).toHaveTextContent(
        "must be a single",
      ),
    );
    // The form stays open so the operator can fix the field.
    expect(screen.getByTestId("taxii-form-name-new")).toHaveValue("Bad feed");
  });

  it("deletes a feed behind a confirmation step", async () => {
    deleteTaxiiFeed.mockResolvedValue(undefined);
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-delete-taxii_ok1")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("taxii-delete-taxii_ok1"));
    // One click is not enough — deleting drops the cursor with the row.
    expect(deleteTaxiiFeed).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("taxii-delete-confirm-taxii_ok1"));
    await waitFor(() =>
      expect(deleteTaxiiFeed).toHaveBeenCalledWith("taxii_ok1"),
    );
    await waitFor(() => expect(listTaxiiFeeds).toHaveBeenCalledTimes(2));
  });

  it("edits a feed through PATCH", async () => {
    updateTaxiiFeed.mockResolvedValue({ ...HEALTHY, poll_interval_minutes: 15 });
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-edit-taxii_ok1")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("taxii-edit-taxii_ok1"));
    // The form prefills from the row, including the reference (config, not
    // material — nothing resolved it).
    expect(screen.getByTestId("taxii-form-auth-ref-taxii_ok1")).toHaveValue(
      "${secret:vault:taxii/cisa#token}",
    );
    fireEvent.change(screen.getByTestId("taxii-form-interval-taxii_ok1"), {
      target: { value: "15" },
    });
    fireEvent.click(screen.getByTestId("taxii-form-save-taxii_ok1"));

    await waitFor(() => expect(updateTaxiiFeed).toHaveBeenCalledTimes(1));
    // Only the changed field is patched — the audit ledger records
    // {"fields": ["poll_interval_minutes"]}, not the whole form.
    expect(updateTaxiiFeed).toHaveBeenCalledWith("taxii_ok1", {
      poll_interval_minutes: 15,
    });
  });

  it("sends no PATCH when the edit form is unchanged", async () => {
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-edit-taxii_ok1")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("taxii-edit-taxii_ok1"));
    fireEvent.click(screen.getByTestId("taxii-form-save-taxii_ok1"));

    await waitFor(() =>
      expect(
        screen.queryByTestId("taxii-form-save-taxii_ok1"),
      ).not.toBeInTheDocument(),
    );
    expect(updateTaxiiFeed).not.toHaveBeenCalled();
  });

  it("blanks the reference when auth is switched off, so the pair validates", async () => {
    updateTaxiiFeed.mockResolvedValue({
      ...HEALTHY,
      auth_style: "none",
      auth_secret_ref: "",
    });
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-edit-taxii_ok1")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("taxii-edit-taxii_ok1"));
    fireEvent.change(screen.getByTestId("taxii-form-auth-style-taxii_ok1"), {
      target: { value: "none" },
    });
    fireEvent.click(screen.getByTestId("taxii-form-save-taxii_ok1"));

    await waitFor(() => expect(updateTaxiiFeed).toHaveBeenCalledTimes(1));
    expect(updateTaxiiFeed).toHaveBeenCalledWith("taxii_ok1", {
      auth_style: "none",
      auth_secret_ref: "",
    });
  });

  it("renders read-only for senior_analyst — taxii:view without taxii:manage", async () => {
    currentRole = "senior_analyst";
    render(<TaxiiFeedsPanel />);

    await waitFor(() =>
      expect(screen.getByTestId("taxii-feed-row-taxii_ok1")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("taxii-feed-add")).not.toBeInTheDocument();
    expect(screen.queryByTestId("taxii-edit-taxii_ok1")).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("taxii-delete-taxii_ok1"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("taxii-readonly-note")).toBeInTheDocument();
  });

  it("hides itself for a role without taxii:view", async () => {
    currentRole = "analyst";
    const { container } = render(<TaxiiFeedsPanel />);

    await waitFor(() => expect(container).toBeEmptyDOMElement());
    // No request is made for a role the endpoint would 403.
    expect(listTaxiiFeeds).not.toHaveBeenCalled();
  });

  it("hides itself when the list call 403s", async () => {
    listTaxiiFeeds.mockRejectedValue(new ApiError(403, "Forbidden", null));
    const { container } = render(<TaxiiFeedsPanel />);

    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
