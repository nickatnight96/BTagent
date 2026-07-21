/**
 * Detection Proposals review page (#113).
 *
 * Surfaces the CTI → Detection proposal store (STIX 2.1 bundle → Sigma rule
 * proposals) for analyst review. Proposals are listed newest-first with a
 * state filter; a proposed rule can be accepted or rejected (with an optional
 * rationale) — the HITL review gate before a rule is promoted to a PR.
 *
 * RBAC is enforced server-side: hunt:view to read, hunt:triage to accept /
 * reject. A viewer without triage authority sees a 403 surfaced as the error
 * banner.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { FlaskConical, Loader2, RefreshCw, Check, X, ChevronDown, ChevronRight } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { listProposals, acceptProposal, rejectProposal } from "@/api/detection";
import type { DetectionProposal, ProposalState } from "@/types/detection";

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

export function DetectionProposalsPage() {
  const [proposals, setProposals] = useState<DetectionProposal[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState<StateFilter>("all");
  const [isLoading, setIsLoading] = useState(false);
  const [mutatingId, setMutatingId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const fetchProposals = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await listProposals(filter === "all" ? undefined : { state: filter });
      setProposals(resp.items);
      setTotal(resp.total);
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

  const toggleExpanded = (id: string) => {
    setExpanded((prev) => {
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
              return (
                <Card key={p.id} data-testid={`proposal-${p.id}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className={`inline-block rounded border px-1.5 py-0.5 text-[10px] uppercase ${stateBadgeClass(p.state)}`}
                          >
                            {p.state}
                          </span>
                          <h3 className="truncate font-medium text-foreground">{p.title}</h3>
                        </div>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {p.technique_ids.join(", ") || "no techniques"} · confidence{" "}
                          {Math.round(p.confidence * 100)}%
                        </p>
                      </div>
                      {p.state === "proposed" && (
                        <div className="flex shrink-0 items-center gap-2">
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
                        </div>
                      )}
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
      </div>
    </div>
  );
}
