/**
 * Cloud IAM containment-proposal API client (#117 Phase C bullet 2 — IAM → IR).
 *
 * Wraps the three routes behind the proposal review surface:
 *
 *   GET    /cloud/investigations/{id}/containment-proposal
 *   POST   /cloud/investigations/{id}/containment-proposal/accept
 *   POST   /cloud/investigations/{id}/containment-proposal/reject
 *
 * The client's whole job beyond transport is telling apart the *three* answers a
 * containment decision can produce, because conflating any two of them would put
 * a lie on screen:
 *
 * 1. **Executed** — 200, and the returned proposal is ``accepted``. At least one
 *    action went through the #106 execute path.
 * 2. **Refused** — 403 whose body is the *proposal itself*, every selected action
 *    marked ``denied`` with a verbatim reason and its audit id. This is a
 *    guardrail doing its job (org never-touch safelist, or the approved-flag
 *    gate), not a transport failure: the server wrote hash-chained DENIED rows
 *    before answering, and the proposal deliberately stays ``proposed`` so the
 *    analyst's decision is not consumed by a refused attempt.
 * 3. **Failed** — anything else (RBAC 403 with a string ``detail``, 404, 409,
 *    500, network error). No decision was recorded, and nothing ran.
 *
 * ``acceptCloudContainmentProposal`` resolves for (1) and (2) — a refusal is an
 * outcome, so callers get the audited denials as data — and rejects for (3).
 */

import api, { ApiError } from "./client";
import type {
  CloudContainmentAction,
  CloudContainmentDecisionRequest,
  CloudContainmentProposal,
} from "@/types/cloud_hunt";

export type {
  CloudContainmentAction,
  CloudContainmentActionStatus,
  CloudContainmentActionType,
  CloudContainmentDecisionRequest,
  CloudContainmentProposal,
  CloudContainmentProposalStatus,
} from "@/types/cloud_hunt";

// The SPA's api client prepends ``/api``, and the backend mounts every v1 route
// under ``/api/v1`` — so this base MUST carry the ``/v1``. A ``/cloud`` base
// still satisfies the reachability guard in
// ``backend/tests/test_api_reachability.py`` (the routers themselves don't carry
// ``/v1``) while 404ing in the browser, which is exactly how the first cut of
// this client shipped unreachable.
const BASE = "/v1/cloud";

/**
 * Accept body with the HITL flag made mandatory.
 *
 * The wire contract leaves ``approved`` optional (the backend defaults it to
 * ``false``), but an *accept* call has to state it explicitly, carrying the
 * operator's confirmation. Never hard-code it to ``true``: the execute service
 * refuses — and audits — anything not marked approved, and the flag is the
 * request's claim about consent, which has to be a true one.
 */
export type ContainmentAcceptRequest = CloudContainmentDecisionRequest & {
  approved: boolean;
};

/**
 * The result of an accept: it ran, or it was refused with an audit trail.
 *
 * ``executed`` is ``true`` only when the server said the proposal is now
 * ``accepted`` — i.e. at least one action actually dispatched. A refusal comes
 * back with ``executed: false`` and the per-action denials on ``proposal``.
 */
export interface ContainmentDecisionOutcome {
  executed: boolean;
  proposal: CloudContainmentProposal;
}

/** Duck-type a body as a containment proposal payload. */
function asProposal(body: unknown): CloudContainmentProposal | null {
  if (!body || typeof body !== "object") return null;
  const candidate = body as Partial<CloudContainmentProposal>;
  if (!Array.isArray(candidate.actions)) return null;
  if (typeof candidate.status !== "string") return null;
  return candidate as CloudContainmentProposal;
}

/**
 * Pull the refused proposal out of an audited 403, or ``null``.
 *
 * The proposal-shaped body is what separates an *audited containment refusal*
 * (safelist / approval gate, ledger rows written, nothing executed) from a plain
 * ``containment:execute`` RBAC 403, which carries a string ``detail`` and leaves
 * no ledger row. Only the former is an outcome worth rendering as a guardrail
 * result; the latter is an error.
 */
export function refusedProposal(e: unknown): CloudContainmentProposal | null {
  if (!(e instanceof ApiError) || e.status !== 403) return null;
  return asProposal(e.body);
}

/** True when the investigation carries no cloud containment proposal (404). */
export function isProposalAbsent(e: unknown): boolean {
  return e instanceof ApiError && e.status === 404;
}

/** Read the inert containment proposal attached to an investigation. */
export async function getCloudContainmentProposal(
  investigationId: string,
): Promise<CloudContainmentProposal> {
  return api.get<CloudContainmentProposal>(
    `${BASE}/investigations/${encodeURIComponent(investigationId)}/containment-proposal`,
  );
}

/**
 * Accept the proposal — routes each selected action through the #106 execute path.
 *
 * Resolves on both an execution and an audited refusal (see
 * {@link ContainmentDecisionOutcome}); rejects on anything that recorded no
 * decision, so a caller can never mistake an RBAC 403 or a 409 for a guardrail
 * denial.
 */
export async function acceptCloudContainmentProposal(
  investigationId: string,
  body: ContainmentAcceptRequest,
): Promise<ContainmentDecisionOutcome> {
  try {
    const proposal = await api.post<CloudContainmentProposal>(
      `${BASE}/investigations/${encodeURIComponent(investigationId)}/containment-proposal/accept`,
      body,
    );
    // Trust the server's own lifecycle verdict rather than re-deriving it: the
    // proposal only reaches `accepted` when at least one action dispatched.
    return { executed: proposal.status === "accepted", proposal };
  } catch (e) {
    const refused = refusedProposal(e);
    if (refused) return { executed: false, proposal: refused };
    throw e;
  }
}

/** Reject the proposal — same decision authority as accept, executes nothing. */
export async function rejectCloudContainmentProposal(
  investigationId: string,
  body: CloudContainmentDecisionRequest,
): Promise<CloudContainmentProposal> {
  return api.post<CloudContainmentProposal>(
    `${BASE}/investigations/${encodeURIComponent(investigationId)}/containment-proposal/reject`,
    body,
  );
}

// ---------------------------------------------------------------------------
// Denial classification
// ---------------------------------------------------------------------------

/**
 * Why an action ended up ``denied``.
 *
 * ``safelist`` — the target is on the org never-touch principal safelist (or is
 *   an account root). The fix is a safelist decision, not a retry.
 * ``approval`` — the request was not marked approved, so the HITL half of the
 *   double-gate refused it. Nothing dispatched.
 * ``failure`` — NOT a guardrail: the action passed both gates, reached the
 *   connector, and the connector reported a failure. The backend files this
 *   under the same ``denied`` action status, but telling an operator "nothing
 *   ran" here would be the mirror image of claiming success — the target's live
 *   state is unverified.
 * ``other`` — an audited denial whose reason we don't recognise; render it
 *   verbatim rather than guessing.
 */
export type ContainmentDenialKind = "safelist" | "approval" | "failure" | "other";

/**
 * Classify a denied action from the server's verbatim reason and outcome.
 *
 * Matches on the two reasons ``containment_execute_service`` emits:
 * "Target is on the org never-touch safelist (collateral-outage guard)." and
 * "Action is not approved (the HITL half of the double-gate is missing)."
 * Unrecognised wording degrades to ``failure`` (when the audit outcome says the
 * dispatch failed) or ``other`` — both of which still render the message
 * verbatim, so a reworded backend reason loses the label, never the reason.
 */
export function denialKind(
  action: Pick<CloudContainmentAction, "message" | "outcome">,
): ContainmentDenialKind {
  const message = action.message.toLowerCase();
  if (message.includes("safelist")) return "safelist";
  if (message.includes("not approved")) return "approval";
  if (action.outcome.toLowerCase() === "failure") return "failure";
  return "other";
}
