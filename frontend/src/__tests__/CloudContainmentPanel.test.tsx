/**
 * Cloud IAM containment proposal review (#117).
 *
 * The backend loop (#511) shipped with no screen, so a promoted cloud IAM/STS
 * finding seeded proposals nobody could see or decide. What matters about the
 * screen that closes it is not that it renders — it is that it cannot lie about
 * the gates:
 *
 * - accept must be unreachable until an explicit confirmation is given, and the
 *   flag on the wire must be that confirmation rather than a hard-coded `true`;
 * - the controls must not exist at all below the `containment:execute` tier;
 * - a safelist refusal is a guardrail *working* — it must read as "nothing ran,
 *   here is the ledger id", never as a failed request, and never as an accepted
 *   proposal.
 *
 * The api client is exercised for real (only `@/api/client`'s transport is
 * faked), because the 403-body-is-the-proposal → refusal translation is exactly
 * the logic that keeps a denial from surfacing as an error.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

const apiGet = vi.fn();
const apiPost = vi.fn();
let mockRole = "incident_commander";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  const api = {
    get: (...a: unknown[]) => apiGet(...a),
    post: (...a: unknown[]) => apiPost(...a),
  };
  return { ...actual, api, default: api };
});

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector?: (s: unknown) => unknown) => {
    const state = { user: { id: "usr_ic", role: mockRole }, logout: vi.fn() };
    return selector ? selector(state) : state;
  },
}));

import { CloudContainmentPanel } from "@/components/workspace/CloudContainmentPanel";
import { ApiError } from "@/api/client";
import type { CloudContainmentProposal } from "@/types/cloud_hunt";

const ACCEPT_URL = "/v1/cloud/investigations/inv_1/containment-proposal/accept";

function proposal(): CloudContainmentProposal {
  return {
    actions: [
      {
        id: "cca_1",
        action_type: "revoke_role",
        provider: "aws",
        target: "arn:aws:iam::111122223333:role/deploy-pivot",
        connector: "aws_iam",
        description: "Revoke active sessions for the pivot hop.",
        parameters: {
          reason: "sts_chaining",
          high_value_target: "arn:aws:iam::111122223333:role/OrgAdmin",
          hop_count: 3,
        },
        source_finding_ids: ["hf_sts_1"],
        status: "proposed",
        outcome: "",
        audit_id: null,
        message: "",
      },
      {
        id: "cca_2",
        action_type: "freeze_access_key",
        provider: "aws",
        target: "arn:aws:iam::111122223333:user/svc-backup",
        connector: "aws_iam",
        description: "Freeze the access key minted by CreateAccessKey.",
        parameters: {
          reason: "iam_persistence",
          event_name: "CreateAccessKey",
          user_name: "svc-backup",
        },
        source_finding_ids: ["hf_persist_1"],
        status: "proposed",
        outcome: "",
        audit_id: null,
        message: "",
      },
    ],
    rationale: "2 cloud IAM containment action(s) proposed from 2 finding(s).",
    status: "proposed",
    decided_by: null,
    decided_at: null,
    decision_rationale: "",
  };
}

/** The 200 an accept returns when both actions dispatched. */
function accepted(): CloudContainmentProposal {
  const p = proposal();
  return {
    ...p,
    status: "accepted",
    decided_by: "usr_ic",
    decided_at: "2026-07-26T12:00:00Z",
    actions: p.actions.map((a, i) => ({
      ...a,
      status: "executed" as const,
      outcome: "success",
      audit_id: `aud_exec_${i + 1}`,
    })),
  };
}

/**
 * The audited 403 a wholly-refused accept returns: the body IS the proposal,
 * still `proposed` (a refusal must not consume the decision), with every action
 * denied and carrying its hash-chained ledger id.
 */
function safelistRefusal(): ApiError {
  const p = proposal();
  const refused: CloudContainmentProposal = {
    ...p,
    // Still `proposed`: the backend does not let a refused attempt consume the
    // analyst's decision.
    status: "proposed",
    actions: p.actions.map((a, i) => ({
      ...a,
      status: "denied" as const,
      outcome: "denied",
      message: "Target is on the org never-touch safelist (collateral-outage guard).",
      audit_id: `aud_denied_${i + 1}`,
    })),
  };
  return new ApiError(403, "Forbidden", refused);
}

async function renderPanel() {
  render(
    <MemoryRouter>
      <CloudContainmentPanel investigationId="inv_1" />
    </MemoryRouter>,
  );
  await screen.findByTestId("containment-review-panel");
}

describe("CloudContainmentPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "incident_commander";
    apiGet.mockResolvedValue(proposal());
  });

  it("reads the proposal from the investigation-scoped route", async () => {
    await renderPanel();
    expect(apiGet).toHaveBeenCalledWith(
      "/v1/cloud/investigations/inv_1/containment-proposal",
    );
  });

  it("shows each action's target, blast radius, reversibility and source finding", async () => {
    await renderPanel();

    expect(screen.getByTestId("containment-review-target-cca_1").textContent).toBe(
      "arn:aws:iam::111122223333:role/deploy-pivot",
    );
    // Blast radius is specialised by the action's own evidence, not boilerplate.
    const blast = screen.getByTestId("containment-review-blast-cca_1").textContent ?? "";
    expect(blast).toContain("Every active STS session");
    expect(blast).toContain("arn:aws:iam::111122223333:role/OrgAdmin");
    expect(
      screen.getByTestId("containment-review-reversibility-cca_2").textContent,
    ).toContain("deactivated, not deleted");
    expect(screen.getByTestId("containment-review-findings-cca_1").textContent).toContain(
      "hf_sts_1",
    );
    // The gate is stated before any control is offered.
    expect(screen.getByTestId("containment-review-gates").textContent).toContain(
      "containment:execute",
    );
  });

  it("will not accept until the approval is explicitly confirmed", async () => {
    apiPost.mockResolvedValue(accepted());
    await renderPanel();

    const accept = screen.getByTestId("containment-review-accept") as HTMLButtonElement;
    expect(accept.disabled).toBe(true);

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    await waitFor(() => expect(accept.disabled).toBe(false));

    fireEvent.change(screen.getByTestId("containment-review-rationale"), {
      target: { value: "Confirmed pivot; commander sign-off." },
    });
    fireEvent.click(accept);
    await screen.findByTestId("containment-review-decided");

    // The confirmation is what lands on the wire as `approved`, and the selected
    // action ids are named explicitly.
    expect(apiPost).toHaveBeenCalledWith(ACCEPT_URL, {
      approved: true,
      rationale: "Confirmed pivot; commander sign-off.",
      action_ids: ["cca_1", "cca_2"],
    });
    expect(screen.getByTestId("containment-review-audit-cca_1").textContent).toBe(
      "aud_exec_1",
    );
    expect(screen.getByTestId("containment-review-status").textContent).toBe("accepted");
  });

  it("accepts only the actions left selected", async () => {
    apiPost.mockResolvedValue(accepted());
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-select-cca_2"));
    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));
    await screen.findByTestId("containment-review-decided");

    expect(apiPost.mock.calls[0]?.[1]).toMatchObject({ action_ids: ["cca_1"] });
  });

  it("offers no decision control below incident commander", async () => {
    mockRole = "senior_analyst";
    await renderPanel();

    expect(screen.queryByTestId("containment-review-accept")).toBeNull();
    expect(screen.queryByTestId("containment-review-reject")).toBeNull();
    expect(screen.queryByTestId("containment-review-approve")).toBeNull();
    // No selection checkboxes either — nothing here is actionable for them.
    expect(screen.queryByTestId("containment-review-select-cca_1")).toBeNull();

    const note = screen.getByTestId("containment-review-decide-denied").textContent ?? "";
    expect(note).toContain("containment:execute");
    expect(note).toContain("nothing has run");
    // The proposal is still undecided; the panel must not imply otherwise.
    expect(screen.getByTestId("containment-review-status").textContent).toBe("proposed");
    expect(apiPost).not.toHaveBeenCalled();
  });

  it("renders a safelist refusal as a guardrail outcome, not a failure", async () => {
    apiPost.mockRejectedValue(safelistRefusal());
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));

    const banner = await screen.findByTestId("containment-review-refused");
    expect(banner.textContent).toContain("nothing executed");
    // A denial is not an error: the error channel stays silent.
    expect(screen.queryByTestId("containment-review-error")).toBeNull();

    const denied = screen.getByTestId("containment-review-denied-cca_1").textContent ?? "";
    expect(denied).toContain("never-touch safelist");
    expect(denied).toContain("nothing ran");
    expect(screen.getByTestId("containment-review-audit-cca_1").textContent).toBe(
      "aud_denied_1",
    );
    // Nothing executed, and the decision was not consumed.
    expect(screen.queryByTestId("containment-review-executed-cca_1")).toBeNull();
    expect(screen.getByTestId("containment-review-status").textContent).toBe("proposed");
    expect(screen.queryByTestId("containment-review-decided")).toBeNull();
  });

  it("does not call a connector failure a guardrail refusal", async () => {
    // The backend files a failed dispatch under the same `denied` action status
    // as a safelist refusal. Only one of the two means "nothing happened", so
    // the panel must not tell the operator the target is untouched.
    const p = proposal();
    apiPost.mockRejectedValue(
      new ApiError(403, "Forbidden", {
        ...p,
        actions: p.actions.map((a) => ({
          ...a,
          status: "denied" as const,
          outcome: "failure",
          message: "aws_iam connector returned an error",
          audit_id: "aud_failed",
        })),
      }),
    );
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));

    const denied = await screen.findByTestId("containment-review-denied-cca_1");
    expect(denied.textContent).toContain("unverified");
    expect(denied.textContent).not.toContain("nothing ran");
    expect(screen.getByTestId("containment-review-refused").textContent).not.toContain(
      "Guardrail refused",
    );
    // Still never claims it executed.
    expect(screen.queryByTestId("containment-review-executed-cca_1")).toBeNull();
  });

  it("re-arms the approval after a refusal instead of leaving it primed", async () => {
    apiPost.mockRejectedValue(safelistRefusal());
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));
    await screen.findByTestId("containment-review-refused");

    // A second accept has to be re-confirmed: consent is per attempt.
    expect(
      (screen.getByTestId("containment-review-accept") as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("reports a transport failure as no decision recorded", async () => {
    apiPost.mockRejectedValue(new Error("network down"));
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));

    const err = await screen.findByTestId("containment-review-error");
    expect(err.textContent).toContain("not recorded");
    expect(screen.queryByTestId("containment-review-refused")).toBeNull();
  });

  it("does not dress an RBAC 403 up as a guardrail refusal", async () => {
    // A bare RBAC 403 carries a string `detail` and leaves no ledger row, so it
    // is an error — mislabelling it would invent an audited denial.
    apiPost.mockRejectedValue(
      new ApiError(403, "Forbidden", {
        detail: "Permission denied: containment:execute requires higher role than analyst",
      }),
    );
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-approve"));
    fireEvent.click(screen.getByTestId("containment-review-accept"));

    await screen.findByTestId("containment-review-error");
    expect(screen.queryByTestId("containment-review-refused")).toBeNull();
    expect(screen.getByTestId("containment-review-status").textContent).toBe("proposed");
  });

  it("rejects without sending an approval", async () => {
    const rejected = proposal();
    rejected.status = "rejected";
    rejected.decided_by = "usr_ic";
    apiPost.mockResolvedValue(rejected);
    await renderPanel();

    fireEvent.click(screen.getByTestId("containment-review-reject"));
    await screen.findByTestId("containment-review-decided");

    expect(apiPost).toHaveBeenCalledWith(
      "/v1/cloud/investigations/inv_1/containment-proposal/reject",
      { approved: false, rationale: "" },
    );
    expect(screen.getByTestId("containment-review-decided").textContent).toContain(
      "nothing was executed",
    );
  });

  it("shows an empty state when the investigation carries no proposal", async () => {
    apiGet.mockRejectedValue(new ApiError(404, "Not Found", { detail: "no proposal" }));
    render(
      <MemoryRouter>
        <CloudContainmentPanel investigationId="inv_2" />
      </MemoryRouter>,
    );
    await screen.findByTestId("containment-review-absent");
    expect(screen.queryByTestId("containment-review-load-error")).toBeNull();
  });
});
