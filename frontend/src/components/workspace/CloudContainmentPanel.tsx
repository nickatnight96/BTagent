/**
 * Cloud IAM containment proposal review (#117 Phase C bullet 2 — IAM → IR).
 *
 * Promoting a cloud IAM/STS hunt finding seeds the Investigation with **inert**
 * containment proposals — revoke role sessions / freeze access key / detach
 * policy. #511 shipped that loop with no screen, so reviewing a proposal was
 * API-only. This panel is the decision surface, mounted in the investigation
 * workspace because the proposal belongs to the case, not to a settings page.
 *
 * The panel's design rule is that **the gates are the content**. Accepting a
 * proposal executes real cloud control-plane containment, so this surface:
 *
 * - names the ``containment:execute`` (incident-commander+) scope, and renders no
 *   accept/reject control at all below that tier (the server re-enforces it —
 *   hiding the button is UX, the 403 is the security);
 * - requires an explicit confirmation whose checked state *is* the request's
 *   ``approved`` flag, the HITL half of the backend's double gate. It is never
 *   hard-coded, so an un-confirmed decision cannot be sent as an approved one;
 * - renders a guardrail refusal (org never-touch safelist, approval gate) as a
 *   **recorded, successful guardrail outcome** with its ledger id — visually and
 *   textually distinct from a request that failed — and never claims an action
 *   ran when the server denied it.
 *
 * Blast radius and reversibility are derived here from the action verb plus the
 * proposal's own evidence parameters; the API returns the action, not this
 * guidance. The panel says so on screen rather than passing it off as server
 * fact.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  ExternalLink,
  Loader2,
  Lock,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { clsx } from "clsx";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { Textarea } from "@/components/ds/textarea";
import {
  acceptCloudContainmentProposal,
  denialKind,
  getCloudContainmentProposal,
  isProposalAbsent,
  rejectCloudContainmentProposal,
  type ContainmentDenialKind,
} from "@/api/cloudContainment";
import {
  CLOUD_CONTAINMENT_ACTION_LABELS,
  CLOUD_PROVIDER_LABELS,
  type CloudContainmentAction,
  type CloudContainmentProposal,
} from "@/types/cloud_hunt";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

// ---------------------------------------------------------------------------
// Derived impact guidance
// ---------------------------------------------------------------------------

/** Who/what stops working if this action runs. */
export interface BlastRadius {
  /** Short scope label for the badge. */
  scope: string;
  /** Sentence naming the collateral, specialised with the action's evidence. */
  detail: string;
  /** Relative reach — drives the badge colour only. */
  level: "high" | "medium" | "low";
}

/** Whether the operator can put things back, and what they need to do it. */
export interface Reversibility {
  label: string;
  detail: string;
}

function asCount(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.length;
  return null;
}

/**
 * Derive the blast radius of one proposed action.
 *
 * Keyed on the containment verb, then sharpened with whatever the proposal's
 * ``parameters`` actually carry (chain destination, hop count, trustee count,
 * policy name). Nothing is invented: when a parameter is absent the sentence
 * simply stays general.
 */
export function blastRadius(action: CloudContainmentAction): BlastRadius {
  const params = action.parameters ?? {};
  switch (action.action_type) {
    case "revoke_role": {
      const trustees = asCount(params.external_trustees);
      const destination =
        typeof params.high_value_target === "string" && params.high_value_target
          ? params.high_value_target
          : null;
      const hops = asCount(params.hop_count);
      const extra: string[] = [];
      if (destination) {
        extra.push(
          `breaks the assume-role pivot toward ${destination}${
            hops !== null ? ` (${hops} hop chain)` : ""
          }`,
        );
      }
      if (trustees !== null && trustees > 0) {
        extra.push(`${trustees} unapproved external trustee(s) lose their path in`);
      }
      return {
        scope: "Role + every consumer",
        level: "high",
        detail:
          "Every active STS session for this role stops immediately. Any workload, " +
          "pipeline or human currently assuming it loses access until it re-assumes" +
          (extra.length ? ` — ${extra.join("; ")}.` : "."),
      };
    }
    case "freeze_access_key": {
      const user =
        typeof params.user_name === "string" && params.user_name ? params.user_name : null;
      return {
        scope: "One credential",
        level: "medium",
        detail:
          "Deactivates this long-lived key, so anything still authenticating with it " +
          `fails on the next call. Scoped to the credential${
            user ? ` minted for ${user}` : ""
          } — the principal keeps its other keys, roles and console access.`,
      };
    }
    case "detach_policy": {
      const policy =
        typeof params.policy_name === "string" && params.policy_name
          ? params.policy_name
          : null;
      return {
        scope: "Principal permissions",
        level: "medium",
        detail:
          `Removes ${policy ? `policy "${policy}"` : "the named policy"} from the ` +
          "principal, so every permission it granted disappears at once — including " +
          "any legitimate use. Other attached policies are untouched.",
      };
    }
  }
}

/**
 * Derive how recoverable one proposed action is.
 *
 * Stated as what the operator has to do to get back, because "reversible" alone
 * would read as "harmless" — re-assuming a role and re-attaching a policy whose
 * document nobody saved are very different recoveries.
 */
export function reversibility(action: CloudContainmentAction): Reversibility {
  switch (action.action_type) {
    case "revoke_role":
      return {
        label: "Recoverable, not undoable",
        detail:
          "Revoked sessions cannot be un-revoked — legitimate consumers recover by " +
          "re-assuming the role. Trust-policy entries stripped alongside are not " +
          "restored automatically.",
      };
    case "freeze_access_key":
      return {
        label: "Reversible",
        detail:
          "The key is deactivated, not deleted: re-activating it in IAM restores " +
          "access with the same credential.",
      };
    case "detach_policy":
      return {
        label: "Reversible with the policy document",
        detail:
          "Re-attaching restores the grant — but an inline policy detached without a " +
          "saved copy of its document is not recoverable from the console. Capture it " +
          "before accepting.",
      };
  }
}

// ---------------------------------------------------------------------------
// Evidence rendering
// ---------------------------------------------------------------------------

const PARAMETER_LABELS: Record<string, string> = {
  reason: "Detection",
  event_name: "Control-plane event",
  hop_count: "Assume-role hops",
  high_value_target: "Chain destination",
  external_trustees: "Unapproved external trustees",
  policy_name: "Policy",
  user_name: "IAM user",
};

const PARAMETER_ORDER = Object.keys(PARAMETER_LABELS);

function formatValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map((v) => formatValue(v)).join(", ");
  return JSON.stringify(value);
}

/**
 * Flatten ``parameters`` into label/value rows.
 *
 * Known keys lead, in a stable order; anything else the backend adds still shows
 * up (under its raw key) rather than being silently dropped — evidence the
 * operator can't see is evidence they can't weigh.
 */
function evidenceRows(params: Record<string, unknown>): { label: string; value: string }[] {
  const keys = [
    ...PARAMETER_ORDER.filter((k) => k in params),
    ...Object.keys(params).filter((k) => !(k in PARAMETER_LABELS)),
  ];
  const rows: { label: string; value: string }[] = [];
  for (const key of keys) {
    const raw = params[key];
    if (raw === null || raw === undefined || raw === "") continue;
    if (Array.isArray(raw) && raw.length === 0) continue;
    rows.push({ label: PARAMETER_LABELS[key] ?? key, value: formatValue(raw) });
  }
  return rows;
}

const DENIAL_HEADLINE: Record<ContainmentDenialKind, string> = {
  safelist: "Refused by the org never-touch safelist — nothing ran",
  approval: "Refused by the approval gate — nothing ran",
  failure: "Connector reported a failure — outcome unverified",
  other: "Refused by a containment guardrail — nothing ran",
};

const DENIAL_NEXT_STEP: Record<ContainmentDenialKind, string> = {
  safelist:
    "This principal is protected against collateral outage. Change the never-touch " +
    "safelist in Settings → Configuration Center if it genuinely should be containable.",
  approval:
    "The request reached the execute service without an approval. Confirm the approval " +
    "checkbox and decide again.",
  failure:
    "This is not a guardrail refusal: both gates passed and the connector was called, " +
    "so the principal's live state is unverified. Check the audit entry and the cloud " +
    "console before deciding again.",
  other: "The reason above is the server's, verbatim. Nothing dispatched.",
};

const LEVEL_VARIANT: Record<BlastRadius["level"], "critical" | "medium" | "low"> = {
  high: "critical",
  medium: "medium",
  low: "low",
};

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

type LoadState = "loading" | "ready" | "absent" | "error";

export function CloudContainmentPanel({ investigationId }: { investigationId: string }) {
  const [proposal, setProposal] = useState<CloudContainmentProposal | null>(null);
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [approved, setApproved] = useState(false);
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState<"accept" | "reject" | null>(null);
  // Distinct from `decisionError`: a refusal is a recorded guardrail outcome,
  // an error means no decision was recorded at all.
  const [refused, setRefused] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // Only incident_commander+ hold `containment:execute` — the same scope the
  // direct /containment/execute/* routes require. The backend enforces it on
  // both the accept AND the reject route; hiding the controls here just stops
  // us offering an analyst a button that can only 403.
  const role = useAuthStore((s) => s.user?.role);
  const canDecide = role === UserRole.INCIDENT_COMMANDER || role === UserRole.ADMIN;

  useEffect(() => {
    let live = true;
    setLoadState("loading");
    setLoadError(null);
    void (async () => {
      try {
        const loaded = await getCloudContainmentProposal(investigationId);
        if (!live) return;
        setProposal(loaded);
        setSelected(Object.fromEntries(loaded.actions.map((a) => [a.id, true])));
        setLoadState("ready");
      } catch (e) {
        if (!live) return;
        if (isProposalAbsent(e)) {
          setLoadState("absent");
          return;
        }
        setLoadError(e instanceof Error ? e.message : "Failed to load proposal");
        setLoadState("error");
      }
    })();
    return () => {
      live = false;
    };
  }, [investigationId]);

  const actions = useMemo(() => proposal?.actions ?? [], [proposal]);
  const selectedIds = useMemo(
    () => actions.filter((a) => selected[a.id]).map((a) => a.id),
    [actions, selected],
  );
  const isPending = proposal?.status === "proposed";
  const executedCount = actions.filter((a) => a.status === "executed").length;
  const deniedCount = actions.filter((a) => a.status === "denied").length;
  // A connector failure lands in the same `denied` bucket as a guardrail
  // refusal, so the summary banner must not call the whole batch a guardrail
  // outcome unless every refusal actually was one.
  const allRefusalsAreGuardrails = actions
    .filter((a) => a.status === "denied")
    .every((a) => denialKind(a) !== "failure");

  const applyDecision = useCallback((next: CloudContainmentProposal) => {
    setProposal(next);
    setSelected(Object.fromEntries(next.actions.map((a) => [a.id, true])));
  }, []);

  const handleAccept = useCallback(async () => {
    // Belt and braces around the disabled button: never send an accept that
    // isn't carrying the operator's explicit approval.
    if (!canDecide || !approved || selectedIds.length === 0) return;
    setSubmitting("accept");
    setDecisionError(null);
    setRefused(false);
    try {
      const outcome = await acceptCloudContainmentProposal(investigationId, {
        // The checkbox IS the flag. Not a literal.
        approved,
        rationale,
        // Sent explicitly even when everything is selected, so a proposal that
        // gained an action server-side can't be accepted unseen.
        action_ids: selectedIds,
      });
      applyDecision(outcome.proposal);
      setRefused(!outcome.executed);
      if (!outcome.executed) setApproved(false);
    } catch (e) {
      setDecisionError(e instanceof Error ? e.message : "Accept failed");
    } finally {
      setSubmitting(null);
    }
  }, [canDecide, approved, selectedIds, investigationId, rationale, applyDecision]);

  const handleReject = useCallback(async () => {
    if (!canDecide) return;
    setSubmitting("reject");
    setDecisionError(null);
    setRefused(false);
    try {
      // Rejecting executes nothing, so it carries no approval — `approved`
      // stays false and the server records a decision only.
      const next = await rejectCloudContainmentProposal(investigationId, {
        approved: false,
        rationale,
      });
      applyDecision(next);
    } catch (e) {
      setDecisionError(e instanceof Error ? e.message : "Reject failed");
    } finally {
      setSubmitting(null);
    }
  }, [canDecide, investigationId, rationale, applyDecision]);

  if (loadState === "loading") {
    return (
      <div
        className="flex h-full items-center justify-center text-sm text-muted-foreground"
        data-testid="containment-review-loading"
      >
        <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
        Loading containment proposal…
      </div>
    );
  }

  if (loadState === "absent") {
    return (
      <div
        className="flex h-full flex-col items-center justify-center p-6 text-center text-sm text-muted-foreground"
        data-testid="containment-review-absent"
      >
        <ShieldCheck className="mb-3 h-9 w-9 text-muted-foreground/60" aria-hidden="true" />
        <p className="font-medium">No cloud containment proposal</p>
        <p className="mt-1 text-xs">
          Proposals appear here when a cloud IAM/STS hunt finding is promoted into this
          investigation.
        </p>
      </div>
    );
  }

  if (loadState === "error" || !proposal) {
    return (
      <div
        className="m-4 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
        role="alert"
        data-testid="containment-review-load-error"
      >
        Could not load the containment proposal: {loadError ?? "unknown error"}
      </div>
    );
  }

  return (
    <div
      className="h-full overflow-y-auto p-4 space-y-4"
      data-testid="containment-review-panel"
    >
      {/* Heading + lifecycle */}
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-primary" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-foreground">
            Cloud IAM containment proposal
          </h2>
          <Badge
            variant={
              proposal.status === "accepted"
                ? "destructive"
                : proposal.status === "rejected"
                  ? "secondary"
                  : "medium"
            }
            data-testid="containment-review-status"
          >
            {proposal.status}
          </Badge>
        </div>
        {proposal.rationale && (
          <p className="text-xs text-muted-foreground">{proposal.rationale}</p>
        )}
        <p className="text-[11px] text-muted-foreground">
          Proposed actions are inert until accepted. Accepting runs each one through the
          audited containment execute path — mock-first dispatch, org never-touch safelist
          screened before anything runs, and a ledger row on every execution and every
          refusal.
        </p>
      </div>

      {/* The gate, stated up front */}
      <div
        className="rounded-md border border-border bg-card/50 p-3 text-[11px] text-muted-foreground space-y-1"
        data-testid="containment-review-gates"
      >
        <p className="flex items-center gap-1.5 font-medium text-foreground">
          <Lock className="h-3.5 w-3.5" aria-hidden="true" />
          Two gates gate this decision
        </p>
        <p>
          <span className="font-medium text-foreground">1. RBAC</span> —{" "}
          <span className="font-mono">containment:execute</span>, held by incident
          commanders and admins.{" "}
          {canDecide ? (
            <span className="text-foreground">Your role holds it.</span>
          ) : (
            <span data-testid="containment-review-rbac-note">
              Your role ({role ?? "unknown"}) does not hold it, so no accept or reject
              control is offered here.
            </span>
          )}
        </p>
        <p>
          <span className="font-medium text-foreground">2. Explicit approval</span> — the
          confirmation below is sent as the request&apos;s{" "}
          <span className="font-mono">approved</span> flag. The execute service refuses,
          and audits, anything not marked approved.
        </p>
      </div>

      {/* Actions */}
      <ul className="space-y-3" data-testid="containment-review-actions">
        {actions.map((action) => {
          const radius = blastRadius(action);
          const recovery = reversibility(action);
          const rows = evidenceRows(action.parameters ?? {});
          const denied = action.status === "denied";
          const executed = action.status === "executed";
          const kind = denied ? denialKind(action) : null;
          return (
            <li
              key={action.id}
              className={clsx(
                "rounded-md border p-3 space-y-2",
                // Amber for a guardrail refusal (a safe outcome), red for a
                // connector failure (an unverified one), so the two never read
                // as the same event.
                kind === "failure"
                  ? "border-destructive/40 bg-destructive/10"
                  : denied
                    ? "border-amber-500/40 bg-amber-500/10"
                    : executed
                      ? "border-primary/40 bg-primary/5"
                      : "border-border bg-card/50",
              )}
              data-testid={`containment-review-action-${action.id}`}
            >
              <div className="flex flex-wrap items-center gap-2">
                {isPending && canDecide && (
                  <label className="inline-flex cursor-pointer select-none items-center gap-1.5 text-[11px] font-medium">
                    <input
                      type="checkbox"
                      checked={selected[action.id] ?? false}
                      onChange={() =>
                        setSelected((prev) => ({
                          ...prev,
                          [action.id]: !prev[action.id],
                        }))
                      }
                      className="h-4 w-4 accent-primary"
                      data-testid={`containment-review-select-${action.id}`}
                      aria-label={`Include ${CLOUD_CONTAINMENT_ACTION_LABELS[action.action_type]} on ${action.target}`}
                    />
                    include
                  </label>
                )}
                <span className="text-xs font-semibold text-foreground">
                  {CLOUD_CONTAINMENT_ACTION_LABELS[action.action_type]}
                </span>
                <Badge variant="outline">{CLOUD_PROVIDER_LABELS[action.provider]}</Badge>
                <Badge variant="outline">{action.connector}</Badge>
              </div>

              {/* Target principal */}
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  Target principal
                </p>
                <p
                  className="break-all font-mono text-xs text-foreground"
                  data-testid={`containment-review-target-${action.id}`}
                >
                  {action.target}
                </p>
              </div>

              {action.description && (
                <p className="text-xs text-muted-foreground">{action.description}</p>
              )}

              {/* Blast radius */}
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <AlertTriangle
                    className="h-3.5 w-3.5 text-severity-medium"
                    aria-hidden="true"
                  />
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Blast radius
                  </span>
                  <Badge variant={LEVEL_VARIANT[radius.level]}>{radius.scope}</Badge>
                </div>
                <p
                  className="text-[11px] text-muted-foreground"
                  data-testid={`containment-review-blast-${action.id}`}
                >
                  {radius.detail}
                </p>
              </div>

              {/* Reversibility */}
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <RotateCcw className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Reversibility
                  </span>
                  <Badge variant="outline">{recovery.label}</Badge>
                </div>
                <p
                  className="text-[11px] text-muted-foreground"
                  data-testid={`containment-review-reversibility-${action.id}`}
                >
                  {recovery.detail}
                </p>
              </div>

              {/* Evidence it came from */}
              <div className="space-y-1">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  Evidence
                </p>
                {rows.length > 0 && (
                  <dl className="space-y-0.5 text-[11px]">
                    {rows.map((row) => (
                      <div key={row.label} className="flex gap-1.5">
                        <dt className="shrink-0 text-muted-foreground">{row.label}:</dt>
                        <dd className="break-all font-mono text-foreground">{row.value}</dd>
                      </div>
                    ))}
                  </dl>
                )}
                <p
                  className="text-[11px] text-muted-foreground"
                  data-testid={`containment-review-findings-${action.id}`}
                >
                  From finding{action.source_finding_ids.length === 1 ? "" : "s"}:{" "}
                  {action.source_finding_ids.length > 0 ? (
                    <span className="break-all font-mono text-foreground">
                      {action.source_finding_ids.join(", ")}
                    </span>
                  ) : (
                    "none recorded"
                  )}
                </p>
              </div>

              {/* Outcome, once the action has been through the execute path */}
              {denied && kind && (
                <div
                  className={clsx(
                    "rounded border p-2 text-[11px] space-y-1",
                    kind === "failure"
                      ? "border-destructive/40 bg-destructive/10"
                      : "border-amber-500/40 bg-amber-500/10",
                  )}
                  role="status"
                  data-testid={`containment-review-denied-${action.id}`}
                >
                  <p
                    className={clsx(
                      "flex items-center gap-1.5 font-medium",
                      kind === "failure" ? "text-destructive" : "text-amber-500",
                    )}
                  >
                    <Ban className="h-3.5 w-3.5" aria-hidden="true" />
                    {DENIAL_HEADLINE[kind]}
                  </p>
                  {action.message && <p className="text-foreground">{action.message}</p>}
                  <p className="text-muted-foreground">{DENIAL_NEXT_STEP[kind]}</p>
                  {action.audit_id && (
                    <p className="text-muted-foreground">
                      Audit entry{" "}
                      <span
                        className="font-mono"
                        data-testid={`containment-review-audit-${action.id}`}
                      >
                        {action.audit_id}
                      </span>
                    </p>
                  )}
                </div>
              )}
              {executed && (
                <div
                  className="rounded border border-primary/40 bg-primary/5 p-2 text-[11px] space-y-1"
                  role="status"
                  data-testid={`containment-review-executed-${action.id}`}
                >
                  <p className="flex items-center gap-1.5 font-medium text-primary">
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                    Executed ({action.outcome || "success"})
                  </p>
                  {action.message && <p className="text-muted-foreground">{action.message}</p>}
                  {action.audit_id && (
                    <p className="text-muted-foreground">
                      Audit entry{" "}
                      <span
                        className="font-mono"
                        data-testid={`containment-review-audit-${action.id}`}
                      >
                        {action.audit_id}
                      </span>
                    </p>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>

      {/* Decision */}
      {isPending ? (
        canDecide ? (
          <div className="space-y-3" data-testid="containment-review-decision">
            <div className="space-y-1.5">
              <label
                htmlFor="containment-review-rationale"
                className="text-[11px] font-medium text-foreground"
              >
                Decision rationale (recorded on the ledger)
              </label>
              <Textarea
                id="containment-review-rationale"
                rows={3}
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Why this containment is (or is not) the right call…"
                className="text-xs"
                data-testid="containment-review-rationale"
              />
            </div>

            <label className="flex cursor-pointer select-none items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-[11px]">
              <input
                type="checkbox"
                checked={approved}
                onChange={() => setApproved((prev) => !prev)}
                className="mt-0.5 h-4 w-4 accent-primary"
                data-testid="containment-review-approve"
              />
              <span className="text-foreground">
                I approve executing {selectedIds.length} selected action(s) against live
                cloud IAM. This sends{" "}
                <span className="font-mono">approved=true</span> — the HITL gate — and
                dispatches through the audited containment path.
              </span>
            </label>

            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="destructive"
                size="sm"
                onClick={() => void handleAccept()}
                disabled={!approved || selectedIds.length === 0 || submitting !== null}
                data-testid="containment-review-accept"
              >
                {submitting === "accept" ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                    Accepting…
                  </>
                ) : (
                  `Accept & execute (${selectedIds.length})`
                )}
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => void handleReject()}
                disabled={submitting !== null}
                data-testid="containment-review-reject"
              >
                {submitting === "reject" ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                    Rejecting…
                  </>
                ) : (
                  "Reject"
                )}
              </Button>
            </div>
            {!approved && (
              <p className="text-[11px] text-muted-foreground">
                Accept stays disabled until you confirm above. Rejecting executes nothing
                and needs no approval.
              </p>
            )}
          </div>
        ) : (
          <div
            className="rounded-md border border-border bg-card/50 p-3 text-[11px] text-muted-foreground"
            data-testid="containment-review-decide-denied"
          >
            Deciding this proposal needs incident-commander sign-off
            (<span className="font-mono">containment:execute</span>) — nothing has run, and
            the proposal is still awaiting a decision.
          </div>
        )
      ) : (
        <div
          className="rounded-md border border-border bg-card/50 p-3 text-[11px] text-muted-foreground space-y-1"
          role="status"
          data-testid="containment-review-decided"
        >
          <p className="font-medium text-foreground">
            {proposal.status === "accepted"
              ? `Accepted — ${executedCount} action(s) executed${
                  deniedCount > 0
                    ? `, ${deniedCount} did not run${
                        allRefusalsAreGuardrails ? " (refused by a guardrail)" : ""
                      }`
                    : ""
                }.`
              : "Rejected — nothing was executed."}
          </p>
          {proposal.decided_by && <p>Decided by {proposal.decided_by}</p>}
          {proposal.decided_at && (
            <p>{new Date(proposal.decided_at).toLocaleString()}</p>
          )}
          {proposal.decision_rationale && <p>“{proposal.decision_rationale}”</p>}
        </div>
      )}

      {/* A wholly-refused accept: a guardrail worked. Not an error. */}
      {refused && (
        <div
          className="rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-[11px] space-y-1"
          role="status"
          data-testid="containment-review-refused"
        >
          <p className="flex items-center gap-1.5 font-medium text-amber-500">
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            {allRefusalsAreGuardrails
              ? "Guardrail refused every selected action — nothing executed"
              : "No action executed — see each action above for why"}
          </p>
          <p className="text-muted-foreground">
            Every refusal is recorded on the audit ledger with your id as approver. Your
            decision was not consumed: the proposal is still awaiting a decision, so you
            can re-decide once the safelist or the target is resolved. See each action
            above for its reason and ledger id.
          </p>
        </div>
      )}

      {/* A request that recorded nothing. Deliberately worded apart. */}
      {decisionError && (
        <div
          className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-[11px] text-destructive"
          role="alert"
          data-testid="containment-review-error"
        >
          The decision was not recorded — the request failed: {decisionError}. Nothing was
          executed; the proposal is unchanged.
        </div>
      )}

      <p className="border-t border-border/50 pt-3 text-[10px] text-muted-foreground">
        Blast radius and reversibility above are derived in the console from the action
        verb and the proposal&apos;s own evidence, not returned by the API. Source findings
        stay browsable in{" "}
        <Link to="/cloud-hunts" className="inline-flex items-center gap-1 underline">
          Cloud Hunts
          <ExternalLink className="h-3 w-3" aria-hidden="true" />
        </Link>
        .
      </p>
    </div>
  );
}
