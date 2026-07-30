/**
 * Cloud containment-proposal client (#117).
 *
 * Two things are pinned here because neither is visible to a component test:
 *
 * 1. **The base path carries `/v1`.** The SPA client prepends `/api` and the
 *    backend mounts every v1 route under `/api/v1`, so a `/cloud` base 404s in
 *    the browser — while still satisfying the path-shape guard in
 *    `backend/tests/test_api_reachability.py`, because the routers themselves
 *    don't carry `/v1`. That combination is how a "wired up" capability ships
 *    unreachable, so the exact URL is asserted. Both consumers (the promotion
 *    modal, which imports from `@/api/cloud`, and the investigation Containment
 *    tab) go through this one client, so both are covered.
 * 2. **A refusal is an outcome, an RBAC 403 is an error.** The accept route
 *    answers a wholly-denied attempt with 403 whose body is the proposal itself;
 *    a bare permission failure answers 403 with a string `detail`. Treating the
 *    two alike would either bury audited denials or invent them.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

const apiGet = vi.fn();
const apiPost = vi.fn();

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  const api = {
    get: (...a: unknown[]) => apiGet(...a),
    post: (...a: unknown[]) => apiPost(...a),
  };
  return { ...actual, api, default: api };
});

// Imported through `@/api/cloud` on purpose: that is the path the promotion-time
// modal uses, and it must resolve to the same client as the workspace panel.
import {
  acceptCloudContainmentProposal,
  getCloudContainmentProposal,
  rejectCloudContainmentProposal,
} from "@/api/cloud";
import { denialKind } from "@/api/cloudContainment";
import { ApiError } from "@/api/client";
import type { CloudContainmentProposal } from "@/types/cloud_hunt";

function proposal(
  status: CloudContainmentProposal["status"] = "proposed",
): CloudContainmentProposal {
  return {
    actions: [
      {
        id: "cca_1",
        action_type: "revoke_role",
        provider: "aws",
        target: "arn:aws:iam::111122223333:role/break-glass",
        connector: "aws_iam",
        description: "",
        parameters: {},
        source_finding_ids: ["hf_1"],
        status: status === "accepted" ? "executed" : "denied",
        outcome: status === "accepted" ? "success" : "denied",
        audit_id: "aud_1",
        message:
          status === "accepted"
            ? ""
            : "Target is on the org never-touch safelist (collateral-outage guard).",
      },
    ],
    rationale: "",
    status,
    decided_by: null,
    decided_at: null,
    decision_rationale: "",
  };
}

describe("cloud containment proposal client", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reads, accepts and rejects under /v1/cloud", async () => {
    apiGet.mockResolvedValue(proposal());
    apiPost.mockResolvedValue(proposal("accepted"));

    await getCloudContainmentProposal("inv_1");
    await acceptCloudContainmentProposal("inv_1", { approved: true });
    await rejectCloudContainmentProposal("inv_1", { rationale: "not warranted" });

    expect(apiGet).toHaveBeenCalledWith(
      "/v1/cloud/investigations/inv_1/containment-proposal",
    );
    expect(apiPost.mock.calls[0]?.[0]).toBe(
      "/v1/cloud/investigations/inv_1/containment-proposal/accept",
    );
    expect(apiPost.mock.calls[1]?.[0]).toBe(
      "/v1/cloud/investigations/inv_1/containment-proposal/reject",
    );
  });

  it("escapes the investigation id rather than pasting it into the path", async () => {
    apiGet.mockResolvedValue(proposal());
    await getCloudContainmentProposal("inv/../secret");
    expect(apiGet).toHaveBeenCalledWith(
      "/v1/cloud/investigations/inv%2F..%2Fsecret/containment-proposal",
    );
  });

  it("resolves a proposal-shaped 403 as a refusal, not a throw", async () => {
    const refused = proposal();
    apiPost.mockRejectedValue(new ApiError(403, "Forbidden", refused));

    const outcome = await acceptCloudContainmentProposal("inv_1", { approved: true });

    expect(outcome.executed).toBe(false);
    // The per-action denials survive, with their ledger ids.
    expect(outcome.proposal.actions[0]?.audit_id).toBe("aud_1");
    expect(denialKind(outcome.proposal.actions[0]!)).toBe("safelist");
    // A refused attempt does not consume the decision.
    expect(outcome.proposal.status).toBe("proposed");
  });

  it("reports executed only when the server says the proposal is accepted", async () => {
    apiPost.mockResolvedValue(proposal("accepted"));
    const outcome = await acceptCloudContainmentProposal("inv_1", { approved: true });
    expect(outcome.executed).toBe(true);
  });

  it("rethrows an RBAC 403 instead of dressing it up as an audited denial", async () => {
    apiPost.mockRejectedValue(
      new ApiError(403, "Forbidden", {
        detail: "Permission denied: containment:execute requires higher role than analyst",
      }),
    );
    await expect(
      acceptCloudContainmentProposal("inv_1", { approved: true }),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("rethrows a 409 on an already-decided proposal", async () => {
    apiPost.mockRejectedValue(
      new ApiError(409, "Conflict", { detail: "Cloud containment proposal already accepted" }),
    );
    await expect(
      acceptCloudContainmentProposal("inv_1", { approved: true }),
    ).rejects.toBeInstanceOf(ApiError);
  });
});
