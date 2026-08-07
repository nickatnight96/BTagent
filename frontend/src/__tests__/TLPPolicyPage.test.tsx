/**
 * The TLP policy page must distinguish channels it can govern from channels
 * it can only describe.
 *
 * Two of the five egress channels (`mcp_return`, `event_emit`) have no
 * `assert_org_policy_allows_egress` call site. Before this, the page rendered
 * them identically to the three that do: same picker button, same dry-run
 * verdict, same red BLOCKED badge. An admin could deny `mcp_return` of
 * AMBER_STRICT, see the product agree, and have configured nothing.
 *
 * These tests pin the distinction at the two surfaces where the belief forms
 * — the create picker and the dry-run result — and pin that the labelling
 * comes from the server rather than a second copy of the vocabulary here.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { ReactElement } from "react";

const listTLPPolicies = vi.fn();
const listEgressKinds = vi.fn();
const createTLPPolicy = vi.fn();
const deleteTLPPolicy = vi.fn();
const evaluateTLPPolicy = vi.fn();

vi.mock("@/api/tlpPolicies", async () => {
  // Keep the real EGRESS_KINDS: the fallback path is part of what is tested,
  // and stubbing the vocabulary would make that assertion vacuous.
  const actual = await vi.importActual<typeof import("@/api/tlpPolicies")>("@/api/tlpPolicies");
  return {
    ...actual,
    listTLPPolicies: (...a: unknown[]) => listTLPPolicies(...a),
    listEgressKinds: (...a: unknown[]) => listEgressKinds(...a),
    createTLPPolicy: (...a: unknown[]) => createTLPPolicy(...a),
    deleteTLPPolicy: (...a: unknown[]) => deleteTLPPolicy(...a),
    evaluateTLPPolicy: (...a: unknown[]) => evaluateTLPPolicy(...a),
  };
});

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (sel?: (s: Record<string, unknown>) => unknown) => {
    const state = {
      user: { id: "usr_test", username: "tester", role: "admin" },
      logout: () => {},
    };
    return sel ? sel(state) : state;
  },
}));

import { TLPPolicyPage } from "@/components/policies/TLPPolicyPage";

const KINDS = [
  { kind: "stix_export", policy_enforced: true },
  { kind: "report_export", policy_enforced: true },
  { kind: "knowledge_ingest", policy_enforced: true },
  { kind: "mcp_return", policy_enforced: false },
  { kind: "event_emit", policy_enforced: false },
];

const renderPage = (ui: ReactElement = <TLPPolicyPage />) =>
  render(<MemoryRouter>{ui}</MemoryRouter>);

beforeEach(() => {
  vi.clearAllMocks();
  listTLPPolicies.mockResolvedValue([]);
  listEgressKinds.mockResolvedValue(KINDS);
});

describe("egress channel picker", () => {
  it("renders every channel the server names, not a local list", async () => {
    renderPage();
    await waitFor(() => expect(listEgressKinds).toHaveBeenCalled());
    for (const { kind } of KINDS) {
      expect(await screen.findByTestId(`egress-kind-${kind}`)).toBeInTheDocument();
    }
  });

  it("marks only the channels the server reports as ungoverned", async () => {
    renderPage();
    const advisory = await screen.findByTestId("egress-kind-mcp_return");
    expect(advisory).toHaveAttribute("data-advisory", "true");
    expect(advisory).toHaveTextContent(/advisory/i);

    const enforced = screen.getByTestId("egress-kind-stix_export");
    expect(enforced).not.toHaveAttribute("data-advisory");
    expect(enforced).not.toHaveTextContent(/advisory/i);
  });

  it("warns before creating a policy scoped to an ungoverned channel", async () => {
    renderPage();
    fireEvent.click(await screen.findByTestId("egress-kind-stix_export"));
    expect(screen.queryByTestId("advisory-channel-warning")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("egress-kind-event_emit"));
    const warning = await screen.findByTestId("advisory-channel-warning");
    expect(warning).toHaveTextContent("event_emit");
    expect(warning).not.toHaveTextContent("stix_export");
  });

  it("treats an empty selection as covering the ungoverned channels", async () => {
    // Empty means "any channel" on the backend. Showing no warning for the
    // broadest policy in the system is the one reading that is backwards.
    renderPage();
    const warning = await screen.findByTestId("advisory-channel-warning");
    expect(warning).toHaveTextContent("mcp_return");
    expect(warning).toHaveTextContent("event_emit");
  });

  it("claims nothing is enforced when the channel list cannot be loaded", async () => {
    // Failing open here would upgrade an advisory channel to a governed one
    // in the operator's mind, which is the exact belief this page exists to
    // prevent. All five still render so the form stays usable.
    listEgressKinds.mockRejectedValue(new Error("boom"));
    renderPage();

    const enforced = await screen.findByTestId("egress-kind-stix_export");
    expect(enforced).toHaveAttribute("data-advisory", "true");
    expect(screen.getByTestId("egress-kind-event_emit")).toBeInTheDocument();
  });
});

describe("dry-run result", () => {
  const decision = (policy_enforced: boolean) => ({
    allowed: false,
    effective_tlp: "red",
    action: "deny",
    matched_policy_id: null,
    reason: "default-deny",
    policy_enforced,
  });

  it("flags a verdict that nothing will apply", async () => {
    evaluateTLPPolicy.mockResolvedValue(decision(false));
    renderPage();

    fireEvent.change(await screen.findByLabelText("Egress channel"), {
      target: { value: "mcp_return" },
    });
    fireEvent.click(screen.getByTestId("tlp-evaluate-button"));

    const result = await screen.findByTestId("tlp-evaluate-result");
    expect(result).toHaveTextContent("BLOCKED");
    const note = await screen.findByTestId("tlp-evaluate-unenforced");
    expect(note).toHaveTextContent(/not enforced at runtime/i);
    expect(note).toHaveTextContent("mcp_return");
  });

  it("leaves an enforced verdict unqualified", async () => {
    evaluateTLPPolicy.mockResolvedValue(decision(true));
    renderPage();

    fireEvent.click(await screen.findByTestId("tlp-evaluate-button"));

    expect(await screen.findByTestId("tlp-evaluate-result")).toHaveTextContent("BLOCKED");
    expect(screen.queryByTestId("tlp-evaluate-unenforced")).not.toBeInTheDocument();
  });

  it("names the channel the verdict was computed for, not the current select", async () => {
    // The decision stays on screen after the select changes. Naming the live
    // value would attribute the verdict to a channel it is not about.
    evaluateTLPPolicy.mockResolvedValue(decision(false));
    renderPage();

    const select = await screen.findByLabelText("Egress channel");
    fireEvent.change(select, { target: { value: "event_emit" } });
    fireEvent.click(screen.getByTestId("tlp-evaluate-button"));
    await screen.findByTestId("tlp-evaluate-unenforced");

    fireEvent.change(select, { target: { value: "mcp_return" } });
    expect(screen.getByTestId("tlp-evaluate-unenforced")).toHaveTextContent("event_emit");
  });
});
