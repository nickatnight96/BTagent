/**
 * Detection Proposals review page (#113).
 *
 * Surfaces the CTI → Detection proposal store (STIX 2.1 bundle → Sigma rule
 * proposals) for analyst review. Proposals are listed newest-first with a
 * state filter; a proposed rule can be accepted or rejected (with an optional
 * rationale) — the HITL review gate before a rule is promoted to a PR.
 *
 * Any proposal can be validated against historical telemetry (the verdict —
 * clean / matched / error — lands as a badge on the card). Accepted rules
 * that haven't shipped yet can be selected and composed into a single
 * detection-repo PR; shipped rules show their PR back-link.
 *
 * RBAC is enforced server-side: hunt:view to read, hunt:triage to accept /
 * reject, hunt:run to validate, hunt:promote to compose a PR. A caller
 * without the needed authority sees the failure surfaced as the error banner.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  FlaskConical,
  Loader2,
  RefreshCw,
  Check,
  X,
  ChevronDown,
  ChevronRight,
  Gauge,
  GitPullRequest,
  ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { IocRulesPanel } from "@/components/detection/IocRulesPanel";
import {
  listProposals,
  acceptProposal,
  rejectProposal,
  validateProposal,
  composeDetectionPR,
} from "@/api/detection";
import type {
  ComposePRResponse,
  DetectionProposal,
  ProposalState,
} from "@/types/detection";

type StateFilter = "all" | ProposalState;

const STATE_TABS: { value: StateFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "proposed", label: "Proposed" },
  { value: "accepted", label: "Accepted" },
  { value: "rejected", label: "Rejected" },
];

function stateBadgeClass(state: ProposalState): string {
  switch (state) {
    case "accepted":
      return "bg-emerald-600/20 text-emerald-300 border-emerald-500/30";
    case "rejected":
      return "bg-rose-600/20 text-rose-300 border-rose-500/30";
    case "modified":
      return "bg-amber-600/20 text-amber-300 border-amber-500/30";
    default:
      return "bg-sky-600/20 text-sky-300 border-sky-500/30";
  }
}

// Telemetry verdicts: clean = no historical hits (low-noise rule),
// matched = the rule fired on past telemetry, anything else = backend error.
function verdictBadgeClass(verdict: string): string {
  switch (verdict) {
    case "clean":
      return "bg-emerald-600/20 text-emerald-300 border-emerald-500/30";
    case "matched":
      return "bg-amber-600/20 text-amber-300 border-amber-500/30";
    default:
      return "bg-rose-600/20 text-rose-300 border-rose-500/30";
  }
}

/** Accepted but not yet shipped — the only rows the PR composer takes. */
function isShippable(p: DetectionProposal): boolean {
  return p.state === "accepted" && !p.pr_url;
}

export function DetectionProposalsPage() {
  const [proposals, setProposals] = useState<DetectionProposal[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<StateFilter>("all");
  const [isLoading, setIsLoading] = useState(false);
  const [mutatingId, setMutatingId] = useState<string | null>(null);
  const [validatingId, setValidatingId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [isComposing, setIsComposing] = useState(false);
  const [composeResult, setComposeResult] = useState<ComposePRResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchProposals = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await listProposals(filter === "all" ? undefined : { state: filter });
      setProposals(resp.items);
      setTotal(resp.total);
      // Prune the PR selection to rows that are still visible + shippable.
      setSelected((prev) => {
        const eligible = new Set(resp.items.filter(isShippable).map((p) => p.id));
        return new Set([...prev].filter((id) => eligible.has(id)));
      });
    } catch {
      setError("Failed to load detection proposals.");
    } finally {
      setIsLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    void fetchProposals();
  }, [fetchProposals]);

  const handleDecision = useCallback(
    async (rowId: string, decision: "accept" | "reject") => {
      setMutatingId(rowId);
      setError(null);
      try {
        if (decision === "accept") {
          await acceptProposal(rowId);
        } else {
          await rejectProposal(rowId);
        }
        await fetchProposals();
      } catch {
        setError(`Failed to ${decision} proposal.`);
      } finally {
        setMutatingId(null);
      }
    },
    [fetchProposals],
  );

  const handleValidate = useCallback(async (rowId: string) => {
    setValidatingId(rowId);
    setError(null);
    try {
      const updated = await validateProposal(rowId);
      // The response is the refreshed row — swap it in place, no refetch.
      setProposals((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
    } catch {
      setError("Failed to validate proposal against telemetry.");
    } finally {
      setValidatingId(null);
    }
  }, []);

  const handleComposePR = useCallback(async () => {
    if (selected.size === 0) return;
    setIsComposing(true);
    setError(null);
    setComposeResult(null);
    try {
      const result = await composeDetectionPR([...selected]);
      setComposeResult(result);
      setSelected(new Set());
      await fetchProposals();
    } catch {
      setError("Failed to compose detection PR.");
    } finally {
      setIsComposing(false);
    }
  }, [selected, fetchProposals]);

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelected = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const emptyLabel = useMemo(
    () => (filter === "all" ? "No detection proposals yet." : `No ${filter} proposals.`),
    [filter],
  );

  return (
    <div className="flex flex-col h-full" data-testid="detection-proposals">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-violet-600/20 border border-violet-500/30">
            <FlaskConical className="w-4 h-4 text-violet-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Detection Proposals</h1>
            <p className="text-sm text-muted-foreground">
              {total} proposal{total === 1 ? "" : "s"} · STIX → Sigma review queue
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <Button
              size="sm"
              onClick={() => void handleComposePR()}
              disabled={isComposing}
              data-testid="compose-pr-button"
              title="Ship the selected accepted rules as one detection-repo PR"
            >
              {isComposing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <GitPullRequest className="w-4 h-4" />
              )}
              <span className="ml-1">Compose PR ({selected.size})</span>
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void fetchProposals()}
            disabled={isLoading}
            data-testid="proposals-refresh"
            title="Refresh the proposal queue"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
          </Button>
        </div>
      </div>

      {/* ---- State filter ---- */}
      <div className="px-6 pt-4">
        <Tabs value={filter} onValueChange={(v) => setFilter(v as StateFilter)}>
          <TabsList>
            {STATE_TABS.map((t) => (
              <TabsTrigger key={t.value} value={t.value} data-testid={`proposals-tab-${t.value}`}>
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      {/* ---- Body ---- */}
      <div className="flex-1 overflow-auto p-6">
        {error && (
          <div
            className="mb-4 rounded-md border border-rose-500/30 bg-rose-600/10 px-4 py-2 text-sm text-rose-300"
            data-testid="proposals-error"
          >
            {error}
          </div>
        )}

        {composeResult && (
          <div
            className="mb-4 flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-600/10 px-4 py-2 text-sm text-emerald-300"
            data-testid="compose-pr-result"
          >
            <GitPullRequest className="w-4 h-4 shrink-0" />
            <span>
              Shipped {composeResult.rule_count} rule
              {composeResult.rule_count === 1 ? "" : "s"} on{" "}
              <code className="text-xs">{composeResult.branch}</code>
              {composeResult.is_mock ? " (mock git)" : ""} —{" "}
              <a
                href={composeResult.pr_url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 underline hover:text-emerald-200"
              >
                view PR
                <ExternalLink className="w-3 h-3" />
              </a>
            </span>
          </div>
        )}

        {proposals.length === 0 && !isLoading ? (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              {emptyLabel}
            </CardContent>
          </Card>
        ) : (
          <div className="flex flex-col gap-3">
            {proposals.map((p) => {
              const isOpen = expanded.has(p.id);
              const isMutating = mutatingId === p.id;
              const isValidating = validatingId === p.id;
              const verdict =
                typeof p.validation?.verdict === "string" ? p.validation.verdict : null;
              const totalHits =
                typeof p.validation?.total_hits === "number" ? p.validation.total_hits : null;
              return (
                <Card key={p.id} data-testid={`proposal-${p.id}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex min-w-0 items-start gap-3">
                        {isShippable(p) && (
                          <input
                            type="checkbox"
                            checked={selected.has(p.id)}
                            onChange={() => toggleSelected(p.id)}
                            className="mt-1 h-4 w-4 shrink-0 accent-violet-500"
                            aria-label={`Select ${p.title} for the detection PR`}
                            data-testid={`proposal-select-${p.id}`}
                          />
                        )}
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`inline-block rounded border px-1.5 py-0.5 text-[10px] uppercase ${stateBadgeClass(p.state)}`}
                            >
                              {p.state}
                            </span>
                            {verdict && (
                              <span
                                className={`inline-block rounded border px-1.5 py-0.5 text-[10px] uppercase ${verdictBadgeClass(verdict)}`}
                                title={
                                  totalHits === null
                                    ? "Telemetry validation verdict"
                                    : `${totalHits} historical hit${totalHits === 1 ? "" : "s"}`
                                }
                                data-testid={`proposal-verdict-${p.id}`}
                              >
                                telemetry: {verdict}
                              </span>
                            )}
                            <h3 className="truncate font-medium text-foreground">{p.title}</h3>
                          </div>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {p.technique_ids.join(", ") || "no techniques"} · confidence{" "}
                            {Math.round(p.confidence * 100)}%
                          </p>
                          {p.pr_url && (
                            <a
                              href={p.pr_url}
                              target="_blank"
                              rel="noreferrer"
                              className="mt-1 inline-flex items-center gap-1 text-xs text-violet-300 underline hover:text-violet-200"
                              data-testid={`proposal-pr-${p.id}`}
                            >
                              <GitPullRequest className="w-3 h-3" />
                              shipped — view PR
                            </a>
                          )}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={isValidating}
                          onClick={() => void handleValidate(p.id)}
                          data-testid={`proposal-validate-${p.id}`}
                          title="Validate this rule against historical telemetry"
                        >
                          {isValidating ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <Gauge className="w-4 h-4 text-sky-400" />
                          )}
                        </Button>
                        {p.state === "proposed" && (
                          <>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={isMutating}
                              onClick={() => void handleDecision(p.id, "accept")}
                              data-testid={`proposal-accept-${p.id}`}
                              title="Accept this proposal"
                            >
                              {isMutating ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                              ) : (
                                <Check className="w-4 h-4 text-emerald-400" />
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={isMutating}
                              onClick={() => void handleDecision(p.id, "reject")}
                              data-testid={`proposal-reject-${p.id}`}
                              title="Reject this proposal"
                            >
                              <X className="w-4 h-4 text-rose-400" />
                            </Button>
                          </>
                        )}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => toggleExpanded(p.id)}
                      className="mt-3 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                      data-testid={`proposal-toggle-${p.id}`}
                    >
                      {isOpen ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )}
                      {isOpen ? "Hide" : "Show"} Sigma rule
                    </button>
                    {isOpen && (
                      <pre
                        className="mt-2 max-h-72 overflow-auto rounded-md bg-muted/40 p-3 text-xs text-foreground"
                        data-testid={`proposal-sigma-${p.id}`}
                      >
                        {p.sigma_yaml}
                      </pre>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Quick-deploy SIEM rules from a case's IOCs (UC-6.2) — complements
            the formal CTI→Sigma review queue above. */}
        <div className="mt-6">
          <IocRulesPanel />
        </div>
      </div>
    </div>
  );
}
