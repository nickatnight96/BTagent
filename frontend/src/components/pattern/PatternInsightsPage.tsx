/**
 * Pattern Insights page — ranked weak-signal proposals + dismiss / snooze / accept
 * (#120 Phase B).
 *
 * Layout
 * ------
 * 1. Header row with title, total counts, refresh button, and state-filter tabs
 *    (proposed / accepted / dismissed / snoozed / all).
 * 2. Ranked proposal list — each card shows:
 *    - Score badge + rationale (why this pattern surfaced)
 *    - Signal-type chip groups (TTPs / IOCs / adversaries from hunt_input)
 *    - Member-signal count + cross-investigation distinct count
 *    - Source investigation refs (linked to /investigations/:id when possible)
 * 3. Per-proposal inline actions — "Propose a Hunt" (accept), Dismiss, Snooze,
 *    each with an optional rationale textarea.
 * 4. Empty state when no proposals exist for the active filter.
 *
 * RBAC
 * ----
 * - hunt:view   → any analyst+ can see the page.
 * - hunt:triage → dismiss / snooze / accept; gated on analyst+ per rbac.py.
 *
 * Polling: 30-second interval (no WS for Phase B).
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  ExternalLink,
  Loader2,
  RefreshCw,
  Search,
  XCircle,
} from "lucide-react";
import { usePatternStore } from "@/stores/patternStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { Textarea } from "@/components/ds/textarea";
import type { PatternHuntProposal, ProposalFilter, ProposalState } from "@/types/pattern_hunt";

// --------------------------------------------------------------------------- //
// RBAC helpers
// --------------------------------------------------------------------------- //

/**
 * hunt:triage → analyst+. Dismiss / snooze / accept are all gated here.
 * Mirrors the rbac.py entry: "hunt:triage": UserRole.ANALYST.
 */
function useCanTriage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.ANALYST ||
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// --------------------------------------------------------------------------- //
// Constants
// --------------------------------------------------------------------------- //

const POLL_INTERVAL_MS = 30_000;

const STATE_TABS: { id: ProposalFilter; label: string }[] = [
  { id: "proposed", label: "Proposed" },
  { id: "accepted", label: "Accepted" },
  { id: "dismissed", label: "Dismissed" },
  { id: "snoozed", label: "Snoozed" },
  { id: "all", label: "All" },
];

const STATE_STYLES: Record<ProposalState, string> = {
  proposed: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  accepted: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
  dismissed: "bg-slate-700/50 text-slate-400 border-slate-600/30",
  snoozed: "bg-amber-500/10 text-amber-300 border-amber-500/20",
};

// --------------------------------------------------------------------------- //
// Score bar
// --------------------------------------------------------------------------- //

function ScoreBar({ score, maxScore }: { score: number; maxScore: number }) {
  const pct = maxScore > 0 ? Math.min((score / maxScore) * 100, 100) : 0;
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1.5 rounded-full bg-slate-700/60">
        <div
          className="h-1.5 rounded-full bg-violet-500/70"
          style={{ width: `${pct}%` }}
          aria-label={`Score ${score.toFixed(3)}`}
        />
      </div>
      <span className="text-[11px] text-slate-400 tabular-nums w-10 text-right">
        {score.toFixed(3)}
      </span>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// State badge
// --------------------------------------------------------------------------- //

function StateBadge({ state }: { state: ProposalState }) {
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${STATE_STYLES[state]}`}
      data-testid="pattern-state-badge"
      data-state={state}
    >
      {state}
    </span>
  );
}

// --------------------------------------------------------------------------- //
// Signal chips
// --------------------------------------------------------------------------- //

function SignalChips({ proposal }: { proposal: PatternHuntProposal }) {
  const { ttps, iocs, adversaries } = proposal.hunt_input;
  const chips: { label: string; colorClass: string }[] = [];

  if (ttps.length > 0) {
    chips.push({
      label: `${ttps.length} TTP${ttps.length === 1 ? "" : "s"}`,
      colorClass: "bg-rose-500/10 text-rose-300 border-rose-500/20",
    });
  }
  if (iocs.length > 0) {
    chips.push({
      label: `${iocs.length} IOC${iocs.length === 1 ? "" : "s"}`,
      colorClass: "bg-orange-500/10 text-orange-300 border-orange-500/20",
    });
  }
  if (adversaries.length > 0) {
    chips.push({
      label: `${adversaries.length} adversar${adversaries.length === 1 ? "y" : "ies"}`,
      colorClass: "bg-purple-500/10 text-purple-300 border-purple-500/20",
    });
  }

  if (chips.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5 mt-1.5">
      {chips.map((c) => (
        <span
          key={c.label}
          className={`px-1.5 py-0.5 rounded text-[11px] border ${c.colorClass}`}
        >
          {c.label}
        </span>
      ))}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Investigation ref list
// --------------------------------------------------------------------------- //

function InvestigationRefs({ refs }: { refs: string[] }) {
  if (refs.length === 0) return null;
  return (
    <div className="mt-2">
      <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
        Source investigations
      </p>
      <div className="flex flex-wrap gap-1.5">
        {refs.map((ref) => (
          <a
            key={ref}
            href={`/investigations/${ref}`}
            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[11px] font-mono
                       bg-slate-800/60 border border-slate-700/50 text-blue-400 hover:text-blue-300
                       hover:border-blue-500/30 transition-colors"
            data-testid="pattern-inv-ref"
            data-inv-id={ref}
          >
            {ref}
            <ExternalLink className="w-2.5 h-2.5 opacity-60" aria-hidden="true" />
          </a>
        ))}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Action panel (dismiss / snooze / accept)
// --------------------------------------------------------------------------- //

function ActionPanel({
  proposal,
  canTriage,
  isMutating,
  onDismiss,
  onSnooze,
  onAccept,
}: {
  proposal: PatternHuntProposal;
  canTriage: boolean;
  isMutating: boolean;
  onDismiss: (proposalId: string, rationale: string) => Promise<void>;
  onSnooze: (proposalId: string, rationale: string) => Promise<void>;
  onAccept: (proposalId: string) => Promise<void>;
}) {
  const [rationale, setRationale] = useState("");
  const [pending, setPending] = useState<"dismiss" | "snooze" | "accept" | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  // Already-actioned proposals — show read-only state label instead of buttons.
  if (proposal.state !== "proposed") {
    return (
      <div className="mt-3 pt-3 border-t border-slate-700/40">
        <StateBadge state={proposal.state} />
      </div>
    );
  }

  if (!canTriage) return null;

  async function handleDismiss() {
    setPending("dismiss");
    setLocalError(null);
    try {
      await onDismiss(proposal.id, rationale.trim());
      setRationale("");
    } catch {
      // error surfaced in store
    } finally {
      setPending(null);
    }
  }

  async function handleSnooze() {
    setPending("snooze");
    setLocalError(null);
    try {
      await onSnooze(proposal.id, rationale.trim());
      setRationale("");
    } catch {
      // error surfaced in store
    } finally {
      setPending(null);
    }
  }

  async function handleAccept() {
    setPending("accept");
    setLocalError(null);
    try {
      await onAccept(proposal.id);
    } catch {
      // error surfaced in store
    } finally {
      setPending(null);
    }
  }

  return (
    <div className="mt-3 space-y-2 border-t border-slate-700/40 pt-3" data-testid="pattern-action-panel">
      {localError && (
        <p className="text-xs text-destructive" role="alert">
          {localError}
        </p>
      )}
      <Textarea
        value={rationale}
        onChange={(e) => setRationale(e.target.value)}
        placeholder="Rationale — why dismiss or snooze? (optional)"
        rows={2}
        className="text-xs"
        disabled={isMutating}
        data-testid="pattern-rationale"
      />
      <div className="flex flex-wrap items-center gap-2">
        {/* Propose a Hunt (accept) */}
        <Button
          size="sm"
          className="h-7 px-3 text-xs bg-violet-600 hover:bg-violet-700 text-white"
          disabled={isMutating}
          onClick={() => void handleAccept()}
          data-testid="pattern-btn-accept"
        >
          {pending === "accept" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
          )}
          Propose a Hunt
        </Button>

        {/* Snooze */}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-amber-400 hover:text-amber-300 hover:bg-amber-500/10"
          disabled={isMutating}
          onClick={() => void handleSnooze()}
          data-testid="pattern-btn-snooze"
        >
          {pending === "snooze" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <Clock className="w-3.5 h-3.5 mr-1" />
          )}
          Snooze
        </Button>

        {/* Dismiss */}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-slate-400 hover:text-slate-300 hover:bg-slate-700/30"
          disabled={isMutating}
          onClick={() => void handleDismiss()}
          data-testid="pattern-btn-dismiss"
        >
          {pending === "dismiss" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <XCircle className="w-3.5 h-3.5 mr-1" />
          )}
          Dismiss
        </Button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Proposal card
// --------------------------------------------------------------------------- //

function ProposalCard({
  proposal,
  maxScore,
  canTriage,
  isMutating,
  onDismiss,
  onSnooze,
  onAccept,
}: {
  proposal: PatternHuntProposal;
  maxScore: number;
  canTriage: boolean;
  isMutating: boolean;
  onDismiss: (proposalId: string, rationale: string) => Promise<void>;
  onSnooze: (proposalId: string, rationale: string) => Promise<void>;
  onAccept: (proposalId: string) => Promise<void>;
}) {
  const [expanded, setExpanded] = useState(false);

  // Collect all investigation refs from the IOC members (if any). The
  // PatternHuntProposal schema stores the investigation refs at the
  // WeakSignal level; Phase B approximates them from the hunt_input IOC
  // list since the cluster member detail isn't returned by the list
  // endpoint. For now, no refs are shown unless drill-down is added in
  // Phase C.
  const allRefs: string[] = [];

  // Count of distinct IOC/TTP signals shown for the "X signals across Y
  // investigations" caption.
  const signalCount =
    proposal.hunt_input.ttps.length +
    proposal.hunt_input.iocs.length +
    proposal.hunt_input.adversaries.length;

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="pattern-proposal-card"
      data-proposal-id={proposal.id}
    >
      {/* Card header */}
      <div className="flex items-start gap-3 px-4 py-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center text-muted-foreground hover:text-foreground mt-0.5 shrink-0"
          aria-label={expanded ? "Collapse proposal" : "Expand proposal"}
          data-testid="pattern-proposal-expand"
        >
          {expanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>

        <div className="flex flex-1 items-start justify-between gap-3 min-w-0">
          <button onClick={() => setExpanded((v) => !v)} className="text-left min-w-0 flex-1">
            {/* Rationale headline — first 120 chars; full text in expand */}
            <p
              className="text-sm font-medium text-slate-100 leading-snug line-clamp-2"
              title={proposal.rationale}
              data-testid="pattern-proposal-rationale"
            >
              {proposal.rationale || `Cluster ${proposal.cluster_id}`}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">
              {signalCount} signal{signalCount === 1 ? "" : "s"} · score {proposal.score.toFixed(3)}
            </p>
            <SignalChips proposal={proposal} />
          </button>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <ScoreBar score={proposal.score} maxScore={maxScore} />
            <StateBadge state={proposal.state} />
          </div>
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-slate-700/50 px-4 pb-4 pt-3 space-y-3">
          {/* Full rationale */}
          <div>
            <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
              Why did this surface?
            </p>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {proposal.rationale || "No rationale recorded."}
            </p>
          </div>

          {/* Hunt input detail — TTPs */}
          {proposal.hunt_input.ttps.length > 0 && (
            <div>
              <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                Techniques (TTPs)
              </p>
              <div className="flex flex-wrap gap-1.5">
                {proposal.hunt_input.ttps.map((ttp) => (
                  <span
                    key={ttp}
                    className="px-1.5 py-0.5 rounded text-[11px] font-mono bg-rose-500/10 text-rose-300 border border-rose-500/20"
                    data-testid="pattern-ttp-chip"
                  >
                    {ttp}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          {proposal.hunt_input.iocs.length > 0 && (
            <div>
              <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                IOCs
              </p>
              <div className="flex flex-wrap gap-1.5">
                {proposal.hunt_input.iocs.map((ioc, i) => (
                  <span
                    key={i}
                    className="px-1.5 py-0.5 rounded text-[11px] font-mono bg-orange-500/10 text-orange-300 border border-orange-500/20 truncate max-w-xs"
                    title={ioc.value}
                    data-testid="pattern-ioc-chip"
                  >
                    {ioc.type}: {ioc.value}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Adversaries */}
          {proposal.hunt_input.adversaries.length > 0 && (
            <div>
              <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                Adversaries
              </p>
              <div className="flex flex-wrap gap-1.5">
                {proposal.hunt_input.adversaries.map((adv) => (
                  <span
                    key={adv}
                    className="px-1.5 py-0.5 rounded text-[11px] bg-purple-500/10 text-purple-300 border border-purple-500/20"
                    data-testid="pattern-adversary-chip"
                  >
                    {adv}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Source investigation refs */}
          <InvestigationRefs refs={allRefs} />

          {/* Metadata */}
          <p className="text-[11px] text-slate-600">
            Created {new Date(proposal.created_at).toLocaleString()} ·
            Updated {new Date(proposal.updated_at).toLocaleString()}
          </p>

          {/* Action panel */}
          <ActionPanel
            proposal={proposal}
            canTriage={canTriage}
            isMutating={isMutating}
            onDismiss={onDismiss}
            onSnooze={onSnooze}
            onAccept={onAccept}
          />
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Pagination
// --------------------------------------------------------------------------- //

function Pagination({
  page,
  total,
  pageSize,
  onPage,
}: {
  page: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.ceil(total / pageSize) || 1;
  if (totalPages <= 1) return null;
  return (
    <div
      className="flex items-center justify-between text-xs text-muted-foreground pt-2"
      data-testid="pattern-pagination"
    >
      <span>
        Page {page} of {totalPages} ({total} proposals)
      </span>
      <div className="flex gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          data-testid="pattern-prev"
        >
          Prev
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          data-testid="pattern-next"
        >
          Next
        </Button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Main page
// --------------------------------------------------------------------------- //

export function PatternInsightsPage() {
  const canTriage = useCanTriage();

  const {
    proposals,
    total,
    page,
    pageSize,
    stateFilter,
    isLoading,
    isMutating,
    error,
    fetchProposals,
    setStateFilter,
    setPage,
    dismiss,
    snooze,
    accept,
    clearError,
  } = usePatternStore();

  // Initial load.
  useEffect(() => {
    void fetchProposals();
  }, [fetchProposals]);

  // 30-second polling fallback.
  const scheduleRefetch = useCallback(() => {
    void fetchProposals();
  }, [fetchProposals]);

  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    pollTimerRef.current = setInterval(scheduleRefetch, POLL_INTERVAL_MS);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [scheduleRefetch]);

  // Re-fetch when filter tab changes.
  useEffect(() => {
    void fetchProposals({ page: 1 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stateFilter]);

  // Max score for scaling the score bar (descending order, first item is highest).
  const maxScore = proposals.length > 0 ? (proposals[0]?.score ?? 1) : 1;

  // ----- Handlers -----

  const handleDismiss = useCallback(
    async (proposalId: string, rationale: string) => {
      await dismiss(proposalId, { rationale });
    },
    [dismiss],
  );

  const handleSnooze = useCallback(
    async (proposalId: string, rationale: string) => {
      await snooze(proposalId, { rationale });
    },
    [snooze],
  );

  const handleAccept = useCallback(
    async (proposalId: string) => {
      await accept(proposalId);
    },
    [accept],
  );

  const handleTabChange = (value: string) => {
    clearError();
    setStateFilter(value as ProposalFilter);
  };

  return (
    <div className="flex flex-col h-full" data-testid="pattern-insights-page">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-violet-600/20 border border-violet-500/30">
            <Search className="w-4 h-4 text-violet-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Pattern Insights</h1>
            <p className="text-sm text-muted-foreground">
              {total} proposal{total === 1 ? "" : "s"} · ranked weak-signal patterns
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void fetchProposals()}
          disabled={isLoading}
          data-testid="pattern-refresh"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          <span className="ml-2 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      {/* ---- State filter tabs ---- */}
      <div className="px-6 pt-4 border-b border-border">
        <Tabs value={stateFilter} onValueChange={handleTabChange}>
          <TabsList data-testid="pattern-state-tabs">
            {STATE_TABS.map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                data-testid={`pattern-tab-${t.id}`}
              >
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      {/* ---- RBAC notice ---- */}
      {!canTriage && (
        <div
          className="mx-6 mt-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400"
          data-testid="pattern-rbac-notice"
        >
          Dismiss, snooze, and accept actions require the <strong>analyst</strong> role or higher.
        </div>
      )}

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-3">
          {error && (
            <div
              className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
              role="alert"
              data-testid="pattern-error"
            >
              {error}
            </div>
          )}

          {isLoading && proposals.length === 0 && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading pattern proposals…
            </div>
          )}

          {/* ---- Empty state ---- */}
          {!isLoading && proposals.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Search className="mx-auto mb-3 h-8 w-8 opacity-30" />
                <p className="text-sm">
                  {stateFilter === "all"
                    ? "No pattern proposals yet."
                    : `No ${stateFilter} proposals in this view.`}
                </p>
                {stateFilter === "proposed" && (
                  <p className="text-xs text-muted-foreground mt-1">
                    The weekly corpus scan surfaces cross-investigation patterns. Proposals appear
                    here once at least two closed investigations share a faint observable.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* ---- Proposal cards ---- */}
          {proposals.map((proposal) => (
            <ProposalCard
              key={proposal.id}
              proposal={proposal}
              maxScore={maxScore}
              canTriage={canTriage}
              isMutating={isMutating}
              onDismiss={handleDismiss}
              onSnooze={handleSnooze}
              onAccept={handleAccept}
            />
          ))}

          <Pagination page={page} total={total} pageSize={pageSize} onPage={setPage} />
        </div>
      </div>
    </div>
  );
}
