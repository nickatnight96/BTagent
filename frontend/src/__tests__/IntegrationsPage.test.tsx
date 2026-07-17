import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  render,
  screen,
  waitFor,
  within,
  fireEvent,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listConnectors = vi.fn();
const getConnector = vi.fn();
const listCredentials = vi.fn();
const upsertCredential = vi.fn();
const deleteCredential = vi.fn();

vi.mock("@/api/connectors", () => ({
  listConnectors: (...a: unknown[]) => listConnectors(...a),
  getConnector: (...a: unknown[]) => getConnector(...a),
  listCredentials: (...a: unknown[]) => listCredentials(...a),
  upsertCredential: (...a: unknown[]) => upsertCredential(...a),
  deleteCredential: (...a: unknown[]) => deleteCredential(...a),
}));

// Settable current role — defaults to admin so credential controls render.
// The store is used both with a selector (IntegrationsPage) and bare
// (Header destructures { user, logout }), so support both call styles.
let currentRole = "admin";
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel?: (s: Record<string, unknown>) => unknown) => {
    const state = {
      user: { id: "usr_test", username: "tester", role: currentRole },
      logout: () => {},
    };
    return sel ? sel(state) : state;
  },
}));

import { IntegrationsPage } from "@/components/connectors/IntegrationsPage";

const CROWDSTRIKE = {
  name: "crowdstrike",
  version: "0.1.0",
  description: "CrowdStrike Falcon — detections, host details, containment.",
  transport: "mcp/http",
  auth: "custom",
  query_count: 3,
  action_count: 1,
  stream_count: 0,
  has_hitl_actions: true,
  ocsf_emits: ["detection_finding", "device_inventory"],
};

const SHODAN = {
  name: "shodan",
  version: "0.1.0",
  description: "Shodan — host / service exposure lookup.",
  transport: "http/rest",
  auth: "api_key",
  query_count: 2,
  action_count: 0,
  stream_count: 0,
  has_hitl_actions: false,
  ocsf_emits: ["threat_intelligence"],
};

const CROWDSTRIKE_MANIFEST = {
  name: "crowdstrike",
  version: "0.1.0",
  description: CROWDSTRIKE.description,
  transport: "mcp/http",
  auth: "custom",
  queries: [
    {
      id: "cs_get_detections",
      kind: "query",
      description: "Detections with MITRE mappings.",
      ocsf_emits: ["detection_finding"],
      tlp_egress: "red",
      cost_class: "cheap",
      hitl_required: false,
    },
  ],
  actions: [
    {
      id: "cs_isolate_host",
      kind: "action",
      description: "Network-contain a host.",
      ocsf_emits: [],
      tlp_egress: "red",
      cost_class: "expensive",
      hitl_required: true,
      reversible: true,
      blast_radius: "single_host",
    },
  ],
  streams: [],
};

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("IntegrationsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    currentRole = "admin";
    listCredentials.mockResolvedValue({ items: [], total: 0 });
  });

  it("lists connectors with capability-count and HITL badges", async () => {
    listConnectors.mockResolvedValue({
      items: [CROWDSTRIKE, SHODAN],
      total: 2,
    });
    renderPage(<IntegrationsPage />);

    await waitFor(() =>
      expect(screen.getByTestId("connector-count")).toHaveTextContent(
        "2 connectors installed",
      ),
    );
    expect(
      screen.getByTestId("connector-card-crowdstrike"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("connector-card-shodan")).toBeInTheDocument();
    // CrowdStrike has a HITL action; Shodan does not.
    expect(screen.getByTestId("card-hitl-crowdstrike")).toBeInTheDocument();
    expect(screen.queryByTestId("card-hitl-shodan")).not.toBeInTheDocument();
  });

  it("lazy-loads the full manifest when a connector is expanded", async () => {
    listConnectors.mockResolvedValue({ items: [CROWDSTRIKE], total: 1 });
    getConnector.mockResolvedValue(CROWDSTRIKE_MANIFEST);
    renderPage(<IntegrationsPage />);

    await waitFor(() =>
      expect(
        screen.getByTestId("connector-card-crowdstrike"),
      ).toBeInTheDocument(),
    );
    // Detail not fetched until expanded.
    expect(getConnector).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("connector-toggle-crowdstrike"));

    await waitFor(() =>
      expect(getConnector).toHaveBeenCalledWith("crowdstrike"),
    );
    const detail = await screen.findByTestId("connector-detail-crowdstrike");
    expect(
      within(detail).getByTestId("capability-cs_isolate_host"),
    ).toBeInTheDocument();
    // The isolate action carries a HITL badge in the capability row.
    expect(
      within(detail).getByTestId("hitl-cs_isolate_host"),
    ).toBeInTheDocument();
  });

  it("re-queries with has_actions when the action-only filter is toggled", async () => {
    listConnectors.mockResolvedValue({
      items: [CROWDSTRIKE, SHODAN],
      total: 2,
    });
    renderPage(<IntegrationsPage />);
    await waitFor(() => expect(listConnectors).toHaveBeenCalledTimes(1));
    expect(listConnectors).toHaveBeenLastCalledWith(undefined);

    listConnectors.mockResolvedValue({ items: [CROWDSTRIKE], total: 1 });
    fireEvent.click(screen.getByTestId("filter-actions-only"));

    await waitFor(() =>
      expect(listConnectors).toHaveBeenLastCalledWith({ hasActions: true }),
    );
    await waitFor(() =>
      expect(screen.getByTestId("connector-count")).toHaveTextContent(
        "1 connector installed",
      ),
    );
  });

  it("surfaces a load error", async () => {
    listConnectors.mockRejectedValue(new Error("boom"));
    listCredentials.mockResolvedValue({ items: [], total: 0 });
    renderPage(<IntegrationsPage />);
    await waitFor(() =>
      expect(screen.getByTestId("connectors-error")).toHaveTextContent("boom"),
    );
  });

  it("shows a bound badge and admin can save a credential reference", async () => {
    listConnectors.mockResolvedValue({ items: [CROWDSTRIKE], total: 1 });
    getConnector.mockResolvedValue(CROWDSTRIKE_MANIFEST);
    listCredentials.mockResolvedValue({ items: [], total: 0 });
    upsertCredential.mockResolvedValue({
      connector_name: "crowdstrike",
      secret_ref: "${secret:vault:crowdstrike/api_key}",
      label: "prod",
    });
    renderPage(<IntegrationsPage />);

    await waitFor(() =>
      expect(
        screen.getByTestId("connector-card-crowdstrike"),
      ).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("connector-toggle-crowdstrike"));

    const refInput = await screen.findByTestId(
      "credential-ref-input-crowdstrike",
    );
    const saveBtn = screen.getByTestId("credential-save-crowdstrike");
    // Save is disabled until the reference is well-formed.
    expect(saveBtn).toBeDisabled();
    fireEvent.change(refInput, { target: { value: "raw-secret" } });
    expect(
      screen.getByTestId("credential-invalid-crowdstrike"),
    ).toBeInTheDocument();
    expect(saveBtn).toBeDisabled();

    fireEvent.change(refInput, {
      target: { value: "${secret:vault:crowdstrike/api_key}" },
    });
    await waitFor(() => expect(saveBtn).toBeEnabled());
    fireEvent.click(saveBtn);
    await waitFor(() =>
      expect(upsertCredential).toHaveBeenCalledWith("crowdstrike", {
        secret_ref: "${secret:vault:crowdstrike/api_key}",
        label: "",
      }),
    );
    // The onChanged callback re-fetches bindings.
    expect(listCredentials).toHaveBeenCalledTimes(2);
  });

  it("renders the existing binding and admin can remove it", async () => {
    listConnectors.mockResolvedValue({ items: [CROWDSTRIKE], total: 1 });
    getConnector.mockResolvedValue(CROWDSTRIKE_MANIFEST);
    listCredentials.mockResolvedValue({
      items: [
        {
          connector_name: "crowdstrike",
          secret_ref: "${env:CS_KEY}",
          label: "prod",
          created_by: "usr_1",
          updated_by: "usr_1",
          created_at: "2026-07-01T00:00:00Z",
          updated_at: "2026-07-01T00:00:00Z",
        },
      ],
      total: 1,
    });
    deleteCredential.mockResolvedValue(undefined);
    renderPage(<IntegrationsPage />);

    // Collapsed card shows a "bound" badge.
    await waitFor(() =>
      expect(screen.getByTestId("card-bound-crowdstrike")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("connector-toggle-crowdstrike"));
    expect(
      await screen.findByTestId("credential-bound-crowdstrike"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("credential-remove-crowdstrike"));
    await waitFor(() =>
      expect(deleteCredential).toHaveBeenCalledWith("crowdstrike"),
    );
  });

  it("non-admin sees the reference read-only with no controls", async () => {
    currentRole = "senior_analyst";
    listConnectors.mockResolvedValue({ items: [CROWDSTRIKE], total: 1 });
    getConnector.mockResolvedValue(CROWDSTRIKE_MANIFEST);
    listCredentials.mockResolvedValue({
      items: [
        {
          connector_name: "crowdstrike",
          secret_ref: "${env:CS_KEY}",
          label: "prod",
          created_by: "usr_1",
          updated_by: "usr_1",
          created_at: "2026-07-01T00:00:00Z",
          updated_at: "2026-07-01T00:00:00Z",
        },
      ],
      total: 1,
    });
    renderPage(<IntegrationsPage />);
    await waitFor(() =>
      expect(
        screen.getByTestId("connector-card-crowdstrike"),
      ).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByTestId("connector-toggle-crowdstrike"));

    const panel = await screen.findByTestId("credential-panel-crowdstrike");
    expect(within(panel).getByText(/\$\{env:CS_KEY\}/)).toBeInTheDocument();
    // No editing controls for a non-admin.
    expect(
      screen.queryByTestId("credential-ref-input-crowdstrike"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("credential-save-crowdstrike"),
    ).not.toBeInTheDocument();
  });
});
