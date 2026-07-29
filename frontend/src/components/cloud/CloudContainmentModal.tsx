/**
 * Decision surface for the cloud IAM containment proposal an IAM/STS-flavoured
 * promotion attaches to its investigation (#117 Phase C — mirrors the identity
 * RevocationProposalModal).
 *
 * Accepting routes every SELECTED action through the #106 containment execute
 * path — containment:execute RBAC (incident commander+), the explicit
 * `approved` flag, mock-first dispatch, the org never-touch safelist and an
 * audit row on every execute AND denial are all enforced server-side; this
 * modal grants nothing. Shown BEFORE navigating to the new investigation so
 * the HITL decision isn't lost behind the redirect.
 *
 * Partial accept: each action row carries a checkbox; unchecked actions stay
 * `proposed` on the investigation. Denied actions render with their audit id
 * so the refusal is traceable, not mysterious.
 */
import { useState } from "react";
import { Loader2, ShieldAlert } from "lucide-react";

import { Button } from "@/components/ds/button";
import type { CloudContainmentProposal } from "@/types/cloud_hunt";

const ACTION_LABELS: Record<string, string> = {
  revoke_role: "Revoke role sessions",
  freeze_access_key: "Freeze access key",
  detach_policy: "Detach policy",
};

export function CloudContainmentModal({
  proposal,
  canDecide,
  isMutating,
  error,
  onAccept,
  onReject,
  onDismiss,
}: {
  proposal: CloudContainmentProposal;
  canDecide: boolean;
  isMutating: boolean;
  error: string | null;
  onAccept: (actionIds: string[], rationale: string) => void;
  onReject: (rationale: string) => void;
  onDismiss: () => void;
}) {
  const [rationale, setRationale] = useState("");
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(proposal.actions.map((a) => a.id)),
  );
  const decided = proposal.status !== "proposed";

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="cloud-containment-modal"
    >
      <div className="w-full max-w-lg rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="w-4 h-4 text-rose-400" aria-hidden="true" />
          <h2 className="text-base font-semibold text-slate-100">
            Cloud containment proposed
          </h2>
        </div>
        <p className="text-sm text-slate-400 mb-3">{proposal.rationale}</p>

        <ul
          className="mb-4 max-h-52 overflow-y-auto space-y-1 text-sm"
          data-testid="cloud-containment-actions"
        >
          {proposal.actions.map((a) => (
            <li
              key={a.id}
              className="rounded-md border border-slate-800 bg-slate-800/50 px-3 py-1.5 text-slate-300"
              data-testid="cloud-containment-action"
            >
              <label className="flex items-start gap-2">
                {!decided && canDecide && (
                  <input
                    type="checkbox"
                    checked={selected.has(a.id)}
                    onChange={() => toggle(a.id)}
                    className="mt-1"
                    aria-label={`Include ${a.id}`}
                    data-testid={`cloud-containment-select-${a.id}`}
                  />
                )}
                <span className="min-w-0">
                  <span className="font-medium">
                    {ACTION_LABELS[a.action_type] ?? a.action_type}
                  </span>
                  <span className="ml-2 break-all font-mono text-xs text-slate-400">
                    {a.target}
                  </span>
                  <span className="ml-2 text-xs text-slate-500">{a.provider}</span>
                  {a.status !== "proposed" && (
                    <span
                      className={
                        a.status === "executed"
                          ? "ml-2 text-xs text-emerald-400"
                          : "ml-2 text-xs text-amber-400"
                      }
                      data-testid={`cloud-containment-status-${a.id}`}
                    >
                      {a.status}
                      {a.audit_id ? ` · audit ${a.audit_id}` : ""}
                    </span>
                  )}
                </span>
              </label>
            </li>
          ))}
        </ul>

        {decided ? (
          <div
            className="mb-4 rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-sm text-emerald-400"
            data-testid="cloud-containment-decided"
          >
            Proposal {proposal.status}. Every executed and denied action carries a
            hash-chained audit row.
          </div>
        ) : (
          <>
            {!canDecide && (
              <div className="mb-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400">
                Accepting or rejecting requires the <strong>incident commander</strong> role
                or above (containment:execute).
              </div>
            )}
            <label className="block text-xs text-slate-400 mb-1">Decision rationale</label>
            <textarea
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              rows={2}
              placeholder="Why this containment is (or isn't) warranted"
              className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-3"
              data-testid="cloud-containment-rationale"
            />
          </>
        )}

        {error && (
          <div
            className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            role="alert"
            data-testid="cloud-containment-error"
          >
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={onDismiss}
            disabled={isMutating}
            data-testid="cloud-containment-dismiss"
          >
            {decided ? "Continue to investigation" : "Decide later"}
          </Button>
          {!decided && canDecide && (
            <>
              <Button
                variant="outline"
                size="sm"
                disabled={isMutating}
                onClick={() => onReject(rationale)}
                data-testid="cloud-containment-reject"
              >
                Reject
              </Button>
              <Button
                size="sm"
                disabled={isMutating || selected.size === 0}
                onClick={() => onAccept(Array.from(selected), rationale)}
                data-testid="cloud-containment-accept"
              >
                {isMutating ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <ShieldAlert className="w-4 h-4 mr-2" />
                )}
                Approve &amp; execute selected
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
