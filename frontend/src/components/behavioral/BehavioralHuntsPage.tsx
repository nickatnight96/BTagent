/**
 * Behavioral Hunts page — entity drift dashboard + per-entity drilldown +
 * inline triage (#114 Phase B).
 *
 * Layout
 * ------
 * 1. Header row with title, total counts, refresh button, and intent-filter
 *    tabs (mirrors HuntTriagePage).
 * 2. Entity drift dashboard — top-N entities ranked by drift_score
 *    (count × max_cosine_distance), each as an expandable card.
 * 3. Per-entity drilldown — outliers grouped by profile_type; each outlier row
 *    shows cosine_distance + frequency_rank + raw_event_excerpt (expandable).
 * 4. Inline triage panel — three intent buttons (benign / suspicious /
 *    malicious) + rationale textarea + Promote action.
 * 5. Empty state when no outliers exist.
 *
 * RBAC
 * ----
 * - hunt:view  → anyone with analyst role or above can see the page.
 * - hunt:triage → intent buttons + feedback-benign; gated on senior_analyst+.
 * - hunt:promote → promote button; gated on senior_analyst+.
 *
 * Polling: 30-second interval (same model as HuntTriagePage) — WS upgrade
 * deferred to Phase C.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  ArrowUpRight,
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from "lucide-react";
import { useBehavioralStore, buildEntityDriftSummaries } from "@/stores/behavioralStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { Textarea } from "@/components/ds/textarea";
import type {
  BehavioralOutlier,
  EntityDriftSummary,
  IntentLabel,
  ProfileType,
} from "@/types/behavioral";

// --------------------------------------------------------------------------- //
// RBAC helpers
// --------------------------------------------------------------------------- //

// Triage (intent labels + feedback-benign) maps to backend ``hunt:triage``,
// which the RBAC table grants from ``analyst`` upward — see
// ``backend/btagent_backend/auth/rbac.py``. Hide the buttons only for callers
// below that floor.
function useCanTriage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.ANALYST ||
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// Promote-to-investigation maps to ``hunt:promote``, which the RBAC table
// gates at ``senior_analyst`` upward.
function useCanPromote(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// --------------------------------------------------------------------------- //
// Constants
// --------------------------------------------------------------------------- //

const POLL_INTERVAL_MS = 30_000;

type IntentFilterTab = "all" | IntentLabel;

const INTENT_TABS: { id: IntentFilterTab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "suspicious", label: "Suspicious" },
  { id: "malicious", label: "Malicious" },
  { id: "benign", label: "Benign" },
];

const PROFILE_TYPE_LABELS: Record<ProfileType, string> = {
  cmdline_embedding: "Command-line",
  process_tree_pattern: "Process tree",
  identity_action_sequence: "Identity actions",
  network_egress_profile: "Network egress",
};

// --------------------------------------------------------------------------- //
// Intent badge
// --------------------------------------------------------------------------- //

function IntentBadge({ label }: { label: IntentLabel | null }) {
  if (!label) {
    return (
      <span className="px-2 py-0.5 rounded-full text-[11px] font-medium border bg-slate-700/50 text-slate-400 border-slate-600/30">
        unclassified
      </span>
    );
  }
  const styles: Record<IntentLabel, string> = {
    benign: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
    suspicious: "bg-amber-500/10 text-amber-300 border-amber-500/20",
    malicious: "bg-red-500/10 text-red-300 border-red-500/20",
  };
  return (
    <span
      className={`px-2 py-0.5 rounded-full text-[11px] font-medium border ${styles[label]}`}
      data-testid="behavioral-intent-badge"
      data-intent={label}
    >
      {label}
    </span>
  );
}

// --------------------------------------------------------------------------- //
// Drift score bar
// --------------------------------------------------------------------------- //

function DriftScoreBar({
  score,
  maxScore,
}: {
  score: number;
  maxScore: number;
}) {
  const pct = maxScore > 0 ? Math.min((score / maxScore) * 100, 100) : 0;
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 h-1.5 rounded-full bg-slate-700/60">
        <div
          className="h-1.5 rounded-full bg-rose-500/70"
          style={{ width: `${pct}%` }}
          aria-label={`Drift score ${score.toFixed(2)}`}
        />
      </div>
      <span className="text-[11px] text-slate-400 tabular-nums w-10 text-right">
        {score.toFixed(2)}
      </span>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Inline triage panel
// --------------------------------------------------------------------------- //

function TriagePanel({
  outlier,
  canTriage,
  canPromote,
  isMutating,
  onSetIntent,
  onFeedbackBenign,
  onPromote,
}: {
  outlier: BehavioralOutlier;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSetIntent: (outlierId: string, label: IntentLabel, rationale: string) => Promise<void>;
  onFeedbackBenign: (outlierId: string) => Promise<void>;
  onPromote: (outlierId: string) => void;
}) {
  const [rationale, setRationale] = useState("");
  const [pendingLabel, setPendingLabel] = useState<IntentLabel | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  async function handleIntent(label: IntentLabel) {
    if (!rationale.trim()) {
      setLocalError("Rationale is required before setting an intent verdict.");
      return;
    }
    setLocalError(null);
    setPendingLabel(label);
    try {
      await onSetIntent(outlier.id, label, rationale.trim());
      setRationale("");
      setPendingLabel(null);
    } catch {
      setPendingLabel(null);
    }
  }

  async function handleFeedbackBenign() {
    setLocalError(null);
    try {
      await onFeedbackBenign(outlier.id);
    } catch {
      // error surfaced in parent store
    }
  }

  if (!canTriage) return null;

  return (
    <div className="mt-3 space-y-2 border-t border-slate-700/40 pt-3" data-testid="triage-panel">
      {localError && (
        <p className="text-xs text-destructive" role="alert">
          {localError}
        </p>
      )}
      <Textarea
        value={rationale}
        onChange={(e) => setRationale(e.target.value)}
        placeholder="Rationale — why is this benign, suspicious, or malicious?"
        rows={2}
        className="text-xs"
        disabled={isMutating}
        data-testid="triage-rationale"
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10"
          disabled={isMutating}
          onClick={() => void handleIntent("benign")}
          data-testid="triage-btn-benign"
        >
          {pendingLabel === "benign" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
          )}
          Benign
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-amber-400 hover:text-amber-300 hover:bg-amber-500/10"
          disabled={isMutating}
          onClick={() => void handleIntent("suspicious")}
          data-testid="triage-btn-suspicious"
        >
          {pendingLabel === "suspicious" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <AlertTriangle className="w-3.5 h-3.5 mr-1" />
          )}
          Suspicious
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
          disabled={isMutating}
          onClick={() => void handleIntent("malicious")}
          data-testid="triage-btn-malicious"
        >
          {pendingLabel === "malicious" ? (
            <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
          ) : (
            <XCircle className="w-3.5 h-3.5 mr-1" />
          )}
          Malicious
        </Button>

        {/* Feedback-benign — only shown when label is already benign */}
        {outlier.intent_label === "benign" && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-slate-400 hover:text-slate-300"
            disabled={isMutating}
            onClick={() => void handleFeedbackBenign()}
            data-testid="triage-btn-feedback-benign"
            title="Fold this pattern back into the entity baseline so future events like it are not flagged as outliers"
          >
            Fold into baseline
          </Button>
        )}

        {/* Promote — gated on hunt:promote */}
        {canPromote && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
            disabled={isMutating || outlier.promoted_to_finding_id !== null}
            onClick={() => onPromote(outlier.id)}
            data-testid="triage-btn-promote"
          >
            <ArrowUpRight className="w-3.5 h-3.5 mr-1" />
            {outlier.promoted_to_finding_id !== null ? "Promoted" : "Promote"}
          </Button>
        )}

        {/* Link to promoted finding */}
        {outlier.promoted_to_finding_id && (
          <a
            href={`/hunt`}
            className="text-[11px] text-blue-400 underline hover:text-blue-300 ml-1"
            data-testid="triage-finding-link"
          >
            View in Hunt Triage
          </a>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Outlier row (inside a profile-type group)
// --------------------------------------------------------------------------- //

function OutlierRow({
  outlier,
  canTriage,
  canPromote,
  isMutating,
  onSetIntent,
  onFeedbackBenign,
  onPromote,
}: {
  outlier: BehavioralOutlier;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSetIntent: (outlierId: string, label: IntentLabel, rationale: string) => Promise<void>;
  onFeedbackBenign: (outlierId: string) => Promise<void>;
  onPromote: (outlierId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="border-b border-slate-800 last:border-0 px-4 py-2.5"
      data-testid="behavioral-outlier-row"
      data-outlier-id={outlier.id}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <button
            onClick={() => setExpanded((v) => !v)}
            className="mt-0.5 text-muted-foreground hover:text-foreground shrink-0"
            aria-label={expanded ? "Collapse outlier" : "Expand outlier"}
            data-testid="behavioral-outlier-expand"
          >
            {expanded ? (
              <ChevronDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5" />
            )}
          </button>
          <div className="min-w-0">
            <p className="truncate text-xs text-slate-300 font-mono" title={outlier.event_id}>
              {outlier.event_id}
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">
              {new Date(outlier.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0 text-right">
          {/* Why-is-this-an-outlier indicators */}
          <span
            className="px-1.5 py-0.5 rounded text-[11px] bg-rose-500/10 text-rose-300 border border-rose-500/20"
            title="Cosine distance from entity centroid (higher = more anomalous)"
            data-testid="behavioral-cosine-distance"
          >
            dist {outlier.cosine_distance.toFixed(3)}
          </span>
          <span
            className="px-1.5 py-0.5 rounded text-[11px] bg-slate-700/50 text-slate-400 border border-slate-600/30"
            title="Frequency rank in entity profile (0 = never seen before)"
            data-testid="behavioral-frequency-rank"
          >
            rank {outlier.frequency_rank}
          </span>
          <IntentBadge label={outlier.intent_label} />
        </div>
      </div>

      {expanded && (
        <div className="mt-2 ml-5">
          {/* Raw event excerpt */}
          {outlier.raw_event_excerpt && (
            <pre
              className="text-[11px] text-slate-300 bg-slate-900/60 border border-slate-700/50 rounded p-2 overflow-x-auto whitespace-pre-wrap break-words max-h-48"
              data-testid="behavioral-raw-excerpt"
            >
              {outlier.raw_event_excerpt}
            </pre>
          )}
          {/* Intent rationale */}
          {outlier.intent_rationale && (
            <p className="mt-1.5 text-xs text-slate-400 italic">
              Rationale: {outlier.intent_rationale}
            </p>
          )}

          <TriagePanel
            outlier={outlier}
            canTriage={canTriage}
            canPromote={canPromote}
            isMutating={isMutating}
            onSetIntent={onSetIntent}
            onFeedbackBenign={onFeedbackBenign}
            onPromote={onPromote}
          />
        </div>
      )}
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Entity drilldown card
// --------------------------------------------------------------------------- //

function EntityDrilldownCard({
  summary,
  maxScore,
  canTriage,
  canPromote,
  isMutating,
  onSetIntent,
  onFeedbackBenign,
  onPromote,
}: {
  summary: EntityDriftSummary;
  maxScore: number;
  canTriage: boolean;
  canPromote: boolean;
  isMutating: boolean;
  onSetIntent: (outlierId: string, label: IntentLabel, rationale: string) => Promise<void>;
  onFeedbackBenign: (outlierId: string) => Promise<void>;
  onPromote: (outlierId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  // Group outliers by profile_type.
  const byProfileType = summary.outliers.reduce<Record<string, BehavioralOutlier[]>>(
    (acc, o) => {
      (acc[o.profile_type] ??= []).push(o);
      return acc;
    },
    {},
  );

  const profileTypes = Object.keys(byProfileType) as ProfileType[];

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="behavioral-entity-card"
      data-entity-id={summary.entity_id}
    >
      {/* Entity header */}
      <div className="flex items-start gap-3 px-4 py-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-2 text-muted-foreground hover:text-foreground mt-0.5 shrink-0"
          aria-label={expanded ? "Collapse entity" : "Expand entity"}
          data-testid="behavioral-entity-expand"
        >
          {expanded ? (
            <ChevronDown className="w-4 h-4" />
          ) : (
            <ChevronRight className="w-4 h-4" />
          )}
        </button>

        <div className="flex flex-1 items-start justify-between gap-3 min-w-0">
          <button
            onClick={() => setExpanded((v) => !v)}
            className="text-left min-w-0"
          >
            <p className="text-sm font-medium text-slate-100 truncate" title={summary.canonical_id}>
              {summary.canonical_id}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">
              {summary.kind} · {summary.outlier_count} outlier
              {summary.outlier_count === 1 ? "" : "s"} ·{" "}
              {profileTypes.length} profile type{profileTypes.length === 1 ? "" : "s"}
            </p>
          </button>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <DriftScoreBar score={summary.drift_score} maxScore={maxScore} />
            <span
              className="px-2 py-0.5 rounded-full text-[11px] font-medium border bg-slate-700/50 text-slate-300 border-slate-600/30"
              data-testid="behavioral-entity-kind"
            >
              {summary.kind}
            </span>
          </div>
        </div>
      </div>

      {/* Per-profile-type outlier groups */}
      {expanded && (
        <div className="border-t border-slate-700/50">
          {profileTypes.map((pt) => {
            const ptOutliers = byProfileType[pt] ?? [];
            return (
              <div key={pt} className="border-b border-slate-800 last:border-0">
                <div className="px-4 py-1.5 bg-slate-900/30">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">
                    {PROFILE_TYPE_LABELS[pt] ?? pt}
                  </span>
                  <span className="ml-2 text-[11px] text-slate-600">
                    {ptOutliers.length} outlier{ptOutliers.length === 1 ? "" : "s"}
                  </span>
                </div>
                {ptOutliers.map((o) => (
                  <OutlierRow
                    key={o.id}
                    outlier={o}
                    canTriage={canTriage}
                    canPromote={canPromote}
                    isMutating={isMutating}
                    onSetIntent={onSetIntent}
                    onFeedbackBenign={onFeedbackBenign}
                    onPromote={onPromote}
                  />
                ))}
              </div>
            );
          })}
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
      data-testid="behavioral-pagination"
    >
      <span>
        Page {page} of {totalPages} ({total} outliers)
      </span>
      <div className="flex gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          data-testid="behavioral-prev"
        >
          Prev
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          data-testid="behavioral-next"
        >
          Next
        </Button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Promote modal (lightweight inline)
// --------------------------------------------------------------------------- //

function PromoteConfirmation({
  outlierId,
  isMutating,
  onConfirm,
  onCancel,
}: {
  outlierId: string;
  isMutating: boolean;
  onConfirm: (outlierId: string, techniqueIds: string[]) => Promise<void>;
  onCancel: () => void;
}) {
  const [techniqueInput, setTechniqueInput] = useState("");

  const techniqueIds = techniqueInput
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      data-testid="promote-confirmation-modal"
    >
      <div className="w-full max-w-sm rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl">
        <h2 className="text-base font-semibold text-slate-100 mb-3">
          Promote to Hunt Finding
        </h2>
        <p className="text-sm text-slate-400 mb-4">
          This outlier will be escalated into the Hunt Triage inbox as a new
          finding. You can optionally tag MITRE ATT&amp;CK technique IDs.
        </p>
        <label className="block text-xs text-slate-400 mb-1">
          Technique IDs (comma-separated, optional)
        </label>
        <input
          type="text"
          value={techniqueInput}
          onChange={(e) => setTechniqueInput(e.target.value)}
          placeholder="e.g. T1059.001, T1078"
          className="w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 mb-4"
          data-testid="promote-technique-input"
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={isMutating}>
            Cancel
          </Button>
          <Button
            size="sm"
            disabled={isMutating}
            onClick={() => void onConfirm(outlierId, techniqueIds)}
            data-testid="promote-confirm-btn"
          >
            {isMutating ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <ArrowUpRight className="w-4 h-4 mr-2" />
            )}
            Promote
          </Button>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Main page
// --------------------------------------------------------------------------- //

export function BehavioralHuntsPage() {
  const navigate = useNavigate();
  const canTriage = useCanTriage();
  // Promote is a distinct permission (``hunt:promote``, senior_analyst+).
  const canPromote = useCanPromote();

  const {
    outliers,
    total,
    page,
    pageSize,
    intentFilter,
    isLoading,
    isMutating,
    error,
    fetchOutliers,
    setIntentFilter,
    setPage,
    triageOutlier,
    feedbackBenign: storeFeedbackBenign,
    promote,
    clearError,
  } = useBehavioralStore();

  const [promoteTargetId, setPromoteTargetId] = useState<string | null>(null);

  // Initial load.
  useEffect(() => {
    void fetchOutliers();
  }, [fetchOutliers]);

  // 30-second polling fallback (no WS for Phase B).
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const scheduleRefetch = useCallback(() => {
    void fetchOutliers();
  }, [fetchOutliers]);

  useEffect(() => {
    pollTimerRef.current = setInterval(scheduleRefetch, POLL_INTERVAL_MS);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [scheduleRefetch]);

  // Re-fetch when filter tab changes.
  useEffect(() => {
    void fetchOutliers({ page: 1 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intentFilter]);

  // Client-side entity drift aggregation.
  const driftSummaries = buildEntityDriftSummaries(outliers);
  const maxScore = driftSummaries.length > 0 ? (driftSummaries[0]?.drift_score ?? 1) : 1;

  // ----- Handlers -----

  const handleSetIntent = useCallback(
    async (outlierId: string, label: IntentLabel, rationale: string) => {
      await triageOutlier(outlierId, { intent_label: label, rationale });
    },
    [triageOutlier],
  );

  const handleFeedbackBenign = useCallback(
    async (outlierId: string) => {
      await storeFeedbackBenign(outlierId);
    },
    [storeFeedbackBenign],
  );

  const handlePromoteConfirm = useCallback(
    async (outlierId: string, techniqueIds: string[]) => {
      const findingId = await promote(outlierId, { technique_ids: techniqueIds });
      setPromoteTargetId(null);
      navigate(`/hunt?finding_id=${findingId}`);
    },
    [promote, navigate],
  );

  const handleTabChange = (value: string) => {
    clearError();
    setIntentFilter(value as IntentFilterTab);
  };

  return (
    <div className="flex flex-col h-full" data-testid="behavioral-hunts-page">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-violet-600/20 border border-violet-500/30">
            <Activity className="w-4 h-4 text-violet-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Behavioral Hunts</h1>
            <p className="text-sm text-muted-foreground">
              {driftSummaries.length} entit{driftSummaries.length === 1 ? "y" : "ies"} ·{" "}
              {total} outlier{total === 1 ? "" : "s"}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void fetchOutliers()}
          disabled={isLoading}
          data-testid="behavioral-refresh"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4" />
          )}
          <span className="ml-2 hidden sm:inline">Refresh</span>
        </Button>
      </div>

      {/* ---- Intent filter tabs ---- */}
      <div className="px-6 pt-4 border-b border-border">
        <Tabs value={intentFilter} onValueChange={handleTabChange}>
          <TabsList data-testid="behavioral-intent-tabs">
            {INTENT_TABS.map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                data-testid={`behavioral-tab-${t.id}`}
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
          data-testid="behavioral-rbac-notice"
        >
          Triage and promote actions require the <strong>senior_analyst</strong> role or higher.
        </div>
      )}

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-3">
          {error && (
            <div
              className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
              role="alert"
              data-testid="behavioral-error"
            >
              {error}
            </div>
          )}

          {isLoading && outliers.length === 0 && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading behavioral outliers…
            </div>
          )}

          {/* ---- Empty state ---- */}
          {!isLoading && driftSummaries.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Activity className="mx-auto mb-3 h-8 w-8 opacity-30" />
                <p className="text-sm">
                  {intentFilter === "all"
                    ? "No behavioral outliers detected yet."
                    : `No ${intentFilter} outliers in this view.`}
                </p>
                {intentFilter === "all" && (
                  <p className="text-xs text-muted-foreground mt-1">
                    The baseline-building scheduler runs hourly. Once enough events have been
                    collected to establish per-entity profiles, anomalous activity will appear here.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* ---- Entity drift dashboard ---- */}
          {driftSummaries.map((summary) => (
            <EntityDrilldownCard
              key={summary.entity_id}
              summary={summary}
              maxScore={maxScore}
              canTriage={canTriage}
              canPromote={canPromote}
              isMutating={isMutating}
              onSetIntent={handleSetIntent}
              onFeedbackBenign={handleFeedbackBenign}
              onPromote={(id) => setPromoteTargetId(id)}
            />
          ))}

          <Pagination page={page} total={total} pageSize={pageSize} onPage={setPage} />
        </div>
      </div>

      {/* ---- Promote confirmation modal ---- */}
      {promoteTargetId && (
        <PromoteConfirmation
          outlierId={promoteTargetId}
          isMutating={isMutating}
          onConfirm={handlePromoteConfirm}
          onCancel={() => setPromoteTargetId(null)}
        />
      )}
    </div>
  );
}
