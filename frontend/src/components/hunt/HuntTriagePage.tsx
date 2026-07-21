import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Crosshair,
  ShieldOff,
  ArrowUpRight,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Loader2,
  Mail,
  Bird,
  Radar,
  Zap,
  Clock,
  Bot,
  Cloud,
} from "lucide-react";
import { Severity as ConfigSeverity } from "@/types/config";
import { UserRole } from "@/types/config";
import { SeverityBadge } from "@/components/ds/severity-badge";
import type { HuntFinding, HuntFindingCluster, HuntVertical } from "@/types/hunt";
import { useHuntStore, groupFindingsByCluster, type InboxTab } from "@/stores/huntStore";
import { useAuthStore } from "@/stores/authStore";
import { Tabs, TabsList, TabsTrigger } from "@/components/ds/tabs";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import {
  runEmailHunt,
  runDeceptionHunt,
  runNdrHunt,
  runAgenticHunt,
  runCloudHunt,
  runAllHunts,
  listHuntVerticals,
} from "@/api/hunt";
import { SuppressModal, type SuppressModalTarget } from "./SuppressModal";
import { PromoteModal, type PromoteModalTarget } from "./PromoteModal";
import { EventType } from "@/types/events";
import { useLiveEventRefresh } from "@/hooks/useLiveEventRefresh";

// --------------------------------------------------------------------------- //
// RBAC
// --------------------------------------------------------------------------- //

/**
 * Returns true if the user has the senior_analyst, incident_commander, or admin
 * role — the roles that hold hunt:suppress / hunt:promote permissions.
 */
function useCanTriage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.ADMIN ||
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER
  );
}

function sev(s: string): ConfigSeverity {
  return s as ConfigSeverity;
}

// --------------------------------------------------------------------------- //
// Cluster card
// --------------------------------------------------------------------------- //

function ClusterCard({
  cluster,
  findings,
  selected,
  onToggle,
  onSuppressFinding,
  onPromoteFinding,
  onSuppressCluster,
  onPromoteCluster,
  canTriage,
}: {
  cluster: HuntFindingCluster;
  findings: HuntFinding[];
  selected: string[];
  onToggle: (id: string) => void;
  onSuppressFinding: (f: HuntFinding) => void;
  onPromoteFinding: (f: HuntFinding) => void;
  onSuppressCluster: (c: HuntFindingCluster) => void;
  onPromoteCluster: (c: HuntFindingCluster) => void;
  canTriage: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  const suppressedCount = findings.filter((f) => f.state === "suppressed").length;
  const promotedCount = findings.filter((f) => f.state === "promoted").length;

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="hunt-cluster-card"
      data-cluster-id={cluster.id}
    >
      {/* Cluster header row */}
      <div className="flex w-full items-start gap-3 px-4 py-3">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-2 text-muted-foreground hover:text-foreground mt-0.5 shrink-0"
          aria-label={expanded ? "Collapse cluster" : "Expand cluster"}
          data-testid="hunt-cluster-expand"
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
            className="flex flex-wrap items-center gap-3 min-w-0 text-left"
          >
            <SeverityBadge severity={sev(cluster.severity)} data-testid="hunt-cluster-severity" />
            <span className="text-sm font-medium text-slate-100 min-w-0 break-words">
              {cluster.title}
            </span>
          </button>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {/* Technique chips */}
            <div className="flex flex-wrap gap-1">
              {cluster.technique_ids.slice(0, 4).map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 rounded text-[11px] bg-blue-500/10 text-blue-300 border border-blue-500/20"
                  data-testid="hunt-technique-chip"
                >
                  {t}
                </span>
              ))}
              {cluster.technique_ids.length > 4 && (
                <span className="px-1.5 py-0.5 rounded text-[11px] text-slate-500">
                  +{cluster.technique_ids.length - 4}
                </span>
              )}
            </div>

            {/* Finding count */}
            <span className="text-xs text-slate-400" data-testid="hunt-cluster-count">
              {cluster.finding_count} finding{cluster.finding_count === 1 ? "" : "s"}
            </span>

            {/* State badge */}
            <span
              className={[
                "px-2 py-0.5 rounded-full text-[11px] font-medium border",
                cluster.state === "suppressed"
                  ? "bg-amber-500/10 text-amber-300 border-amber-500/20"
                  : cluster.state === "promoted"
                    ? "bg-blue-500/10 text-blue-300 border-blue-500/20"
                    : "bg-slate-700/50 text-slate-400 border-slate-600/30",
              ].join(" ")}
              data-testid="hunt-cluster-state"
            >
              {cluster.state}
            </span>

            {/* Cluster-level actions (senior only) */}
            {canTriage && (
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onSuppressCluster(cluster)}
                  className="h-7 px-2 text-xs text-slate-400 hover:text-amber-300"
                  data-testid="hunt-cluster-suppress"
                >
                  <ShieldOff className="w-3.5 h-3.5 mr-1" />
                  Suppress
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onPromoteCluster(cluster)}
                  className="h-7 px-2 text-xs text-slate-400 hover:text-blue-300"
                  data-testid="hunt-cluster-promote"
                >
                  <ArrowUpRight className="w-3.5 h-3.5 mr-1" />
                  Promote
                </Button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Summary line when collapsed */}
      {!expanded && (suppressedCount > 0 || promotedCount > 0) && (
        <p className="px-10 pb-2 text-xs text-slate-500">
          {suppressedCount > 0 && `${suppressedCount} suppressed`}
          {suppressedCount > 0 && promotedCount > 0 && " · "}
          {promotedCount > 0 && `${promotedCount} promoted`}
        </p>
      )}

      {/* Member findings */}
      {expanded && (
        <div className="border-t border-slate-700/50">
          {findings.length === 0 && (
            <p className="px-10 py-3 text-xs text-slate-500">
              No visible findings in this cluster.
            </p>
          )}
          {findings.map((f) => (
            <div
              key={f.id}
              className="flex items-center justify-between gap-3 px-10 py-2.5 border-b border-slate-800 last:border-0"
              data-testid="hunt-finding-row"
              data-finding-id={f.id}
            >
              <div className="flex items-center gap-3 min-w-0">
                <input
                  type="checkbox"
                  checked={selected.includes(f.id)}
                  onChange={() => onToggle(f.id)}
                  className="shrink-0"
                  aria-label={`Select finding ${f.title}`}
                  data-testid="hunt-finding-select"
                />
                <div className="min-w-0">
                  <p className="truncate text-sm text-slate-200">{f.title}</p>
                  <p className="truncate text-xs text-slate-500">
                    {f.entities.map((e) => `${e.kind}:${e.value}`).join(", ") || "—"}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {f.state === "suppressed" && (
                  <span className="text-[11px] text-amber-400">suppressed</span>
                )}
                {f.state === "promoted" && f.investigation_id && (
                  <a
                    href={`/investigations/${f.investigation_id}`}
                    className="text-[11px] text-blue-400 underline hover:text-blue-300"
                    data-testid="hunt-finding-investigation-link"
                  >
                    investigation
                  </a>
                )}

                {canTriage && (
                  <>
                    <button
                      onClick={() => onSuppressFinding(f)}
                      disabled={f.state === "suppressed"}
                      className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-amber-300 disabled:opacity-40 disabled:cursor-not-allowed"
                      data-testid="hunt-finding-suppress"
                    >
                      <ShieldOff className="w-3.5 h-3.5" />
                      Suppress
                    </button>
                    <button
                      onClick={() => onPromoteFinding(f)}
                      disabled={f.state === "promoted"}
                      className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-blue-300 disabled:opacity-40 disabled:cursor-not-allowed"
                      data-testid="hunt-finding-promote"
                    >
                      <ArrowUpRight className="w-3.5 h-3.5" />
                      Promote
                    </button>
                  </>
                )}
              </div>
            </div>
          ))}
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
  totalClusters,
  pageSize,
  onPage,
}: {
  page: number;
  totalClusters: number;
  pageSize: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.ceil(totalClusters / pageSize) || 1;
  if (totalPages <= 1) return null;
  return (
    <div
      className="flex items-center justify-between text-xs text-muted-foreground pt-2"
      data-testid="hunt-triage-pagination"
    >
      <span>
        Page {page} of {totalPages} ({totalClusters} clusters)
      </span>
      <div className="flex gap-2">
        <Button
          variant="ghost"
          size="sm"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          data-testid="hunt-triage-prev"
        >
          Prev
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          data-testid="hunt-triage-next"
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

const POLL_INTERVAL_MS = 30_000;

/** The finding-lifecycle events every hunt surface refreshes on. */
export const HUNT_FINDING_EVENTS = [
  EventType.HUNT_FINDING_CREATED,
  EventType.HUNT_FINDING_UPDATED,
  EventType.HUNT_FINDING_SUPPRESSED,
  EventType.HUNT_FINDING_PROMOTED,
] as const;

/** Tab labels; each maps 1:1 onto the server-side state filter. */
const TABS: { id: InboxTab; label: string }[] = [
  { id: "active", label: "Active" },
  { id: "suppressed", label: "Suppressed" },
  { id: "promoted", label: "Promoted" },
];

export function HuntTriagePage() {
  const navigate = useNavigate();
  const canTriage = useCanTriage();

  const {
    clusters,
    findings,
    totalClusters,
    totalFindings,
    activeTab,
    page,
    pageSize,
    isLoading,
    isMutating,
    error,
    selectedFindingIds,
    fetchInbox,
    setTab,
    setPage,
    toggleSelected,
    clearSelection,
  } = useHuntStore();

  const [suppressTarget, setSuppressTarget] = useState<SuppressModalTarget | null>(null);
  const [promoteTarget, setPromoteTarget] = useState<PromoteModalTarget | null>(null);

  // ----- Run an email hunt on demand (email vertical) -----
  const [isRunningEmail, setIsRunningEmail] = useState(false);
  const handleRunEmailHunt = useCallback(async () => {
    setIsRunningEmail(true);
    try {
      await runEmailHunt();
      // New email findings clustered on insert — refresh to surface them.
      await fetchInbox();
    } finally {
      setIsRunningEmail(false);
    }
  }, [fetchInbox]);

  // ----- Run a deception hunt on demand (deception vertical) -----
  const [isRunningDeception, setIsRunningDeception] = useState(false);
  const handleRunDeceptionHunt = useCallback(async () => {
    setIsRunningDeception(true);
    try {
      await runDeceptionHunt();
      // New deception findings clustered on insert — refresh to surface them.
      await fetchInbox();
    } finally {
      setIsRunningDeception(false);
    }
  }, [fetchInbox]);

  // ----- Run an NDR hunt on demand (NDR vertical) -----
  const [isRunningNdr, setIsRunningNdr] = useState(false);
  const handleRunNdrHunt = useCallback(async () => {
    setIsRunningNdr(true);
    try {
      await runNdrHunt();
      // New NDR findings clustered on insert — refresh to surface them.
      await fetchInbox();
    } finally {
      setIsRunningNdr(false);
    }
  }, [fetchInbox]);

  // ----- Run an agentic-misuse hunt on demand (agentic vertical) -----
  const [isRunningAgentic, setIsRunningAgentic] = useState(false);
  const handleRunAgenticHunt = useCallback(async () => {
    setIsRunningAgentic(true);
    try {
      await runAgenticHunt();
      // New agentic findings clustered on insert — refresh to surface them.
      await fetchInbox();
    } finally {
      setIsRunningAgentic(false);
    }
  }, [fetchInbox]);

  // ----- Run a cloud control-plane hunt on demand (cloud vertical) -----
  const [isRunningCloud, setIsRunningCloud] = useState(false);
  const handleRunCloudHunt = useCallback(async () => {
    setIsRunningCloud(true);
    try {
      await runCloudHunt();
      // New cloud findings clustered on insert — refresh to surface them.
      await fetchInbox();
    } finally {
      setIsRunningCloud(false);
    }
  }, [fetchInbox]);

  // ----- Run every vertical in one sweep (email + deception + NDR) -----
  const [isRunningAll, setIsRunningAll] = useState(false);
  const handleRunAllHunts = useCallback(async () => {
    setIsRunningAll(true);
    try {
      await runAllHunts();
      // Findings from all three verticals clustered on insert — refresh once.
      await fetchInbox();
    } finally {
      setIsRunningAll(false);
    }
  }, [fetchInbox]);

  // ----- Findings-vertical schedule status (GET /hunt/verticals) -----
  // Fetched once on mount to badge each run button with its cron cadence.
  // Failure-tolerant: a fetch error just leaves the badges off.
  const [schedules, setSchedules] = useState<Record<string, HuntVertical>>({});
  useEffect(() => {
    let active = true;
    void listHuntVerticals()
      .then((resp) => {
        if (!active) return;
        setSchedules(Object.fromEntries(resp.verticals.map((v) => [v.name, v])));
      })
      .catch(() => {
        /* schedule badges are best-effort; ignore */
      });
    return () => {
      active = false;
    };
  }, []);

  // ----- Initial load + re-fetch when tab changes -----
  // A single effect keyed on `activeTab` covers both cases: mounting triggers it
  // with the initial tab value, and switching tabs triggers it again.
  useEffect(() => {
    void fetchInbox({ page: 1 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  // ----- WS live-refresh / polling fallback -----
  // Shared hook (extracted from this page's original inline effect): WS
  // subscription on HUNT_FINDING_* + 1 s debounce + visibility refresh +
  // 30 s polling safety net.
  useLiveEventRefresh(
    useCallback(() => {
      void fetchInbox();
    }, [fetchInbox]),
    HUNT_FINDING_EVENTS,
    { pollIntervalMs: POLL_INTERVAL_MS },
  );

  const byCluster = useMemo(() => groupFindingsByCluster(findings), [findings]);

  // ----- Tab handling -----
  const handleTabChange = (value: string) => {
    setTab(value as InboxTab);
  };

  // ----- Promote action bar (bulk) -----
  const handleBulkPromote = async () => {
    if (selectedFindingIds.length === 0) return;
    const invId = await useHuntStore.getState().promote(selectedFindingIds);
    navigate(`/investigations/${invId}`);
  };

  // Tab filtering is server-side (state= param, applied before pagination in
  // PR #202), so the returned clusters ARE the current tab's page and
  // totalClusters is exact for the tab — no client-side re-filtering.
  const filteredClusters = clusters;

  // A small "on a cron" badge for a vertical's run button. Renders only when
  // GET /hunt/verticals reported that vertical's schedule as enabled.
  const scheduleBadge = (name: string) => {
    const v = schedules[name];
    if (!v?.schedule_enabled) return null;
    return (
      <span
        data-testid={`hunt-schedule-${name}`}
        title={`Also scheduled every ${v.scan_interval_hours}h`}
        className="ml-1 inline-flex items-center gap-0.5 text-[10px] text-emerald-400"
      >
        <Clock className="w-3 h-3" aria-hidden="true" />
        {v.scan_interval_hours}h
      </span>
    );
  };

  return (
    <div className="flex flex-col h-full" data-testid="hunt-triage">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-rose-600/20 border border-rose-500/30">
            <Crosshair className="w-4 h-4 text-rose-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Hunt Triage</h1>
            <p className="text-sm text-muted-foreground">
              {totalClusters} cluster{totalClusters === 1 ? "" : "s"} ·{" "}
              {totalFindings} finding{totalFindings === 1 ? "" : "s"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunAllHunts()}
            disabled={
              isRunningAll ||
              isRunningEmail ||
              isRunningDeception ||
              isRunningNdr ||
              isRunningAgentic ||
              isRunningCloud
            }
            data-testid="hunt-run-all"
            title="Run every findings vertical (email + deception + NDR) in one sweep"
          >
            {isRunningAll ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Zap className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run all hunts</span>
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunEmailHunt()}
            disabled={isRunningEmail}
            data-testid="hunt-run-email"
            title="Gather email-security telemetry and land phishing findings in the inbox"
          >
            {isRunningEmail ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Mail className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run email hunt</span>
            {scheduleBadge("email")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunDeceptionHunt()}
            disabled={isRunningDeception}
            data-testid="hunt-run-deception"
            title="Gather Thinkst Canary telemetry and land deception findings in the inbox"
          >
            {isRunningDeception ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Bird className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run deception hunt</span>
            {scheduleBadge("deception")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunNdrHunt()}
            disabled={isRunningNdr}
            data-testid="hunt-run-ndr"
            title="Gather Vectra NDR telemetry and land network campaign findings in the inbox"
          >
            {isRunningNdr ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Radar className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run NDR hunt</span>
            {scheduleBadge("ndr")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunAgenticHunt()}
            disabled={isRunningAgentic}
            data-testid="hunt-run-agentic"
            title="Scan agentic-AI telemetry for prompt injection, shadow agents, and identity abuse"
          >
            {isRunningAgentic ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Bot className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run agentic hunt</span>
            {scheduleBadge("agentic")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRunCloudHunt()}
            disabled={isRunningCloud}
            data-testid="hunt-run-cloud"
            title="Scan cloud control-plane telemetry for trust abuse, shadow workloads, and IAM persistence"
          >
            {isRunningCloud ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Cloud className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run cloud hunt</span>
            {scheduleBadge("cloud")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void fetchInbox()}
            disabled={isLoading}
            data-testid="hunt-refresh"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Refresh</span>
          </Button>
        </div>
      </div>

      {/* ---- State filter tabs ---- */}
      <div className="px-6 pt-4 border-b border-border">
        <Tabs value={activeTab} onValueChange={handleTabChange}>
          <TabsList data-testid="hunt-triage-tabs">
            {TABS.map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                data-testid={`hunt-tab-${t.id}`}
              >
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      {/* ---- RBAC notice for plain analysts ---- */}
      {!canTriage && (
        <div
          className="mx-6 mt-3 rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-xs text-amber-400"
          data-testid="hunt-rbac-notice"
        >
          Suppress and promote actions require the <strong>senior_analyst</strong> role or
          higher.
        </div>
      )}

      {/* ---- Content ---- */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-3">
          {error && (
            <div
              className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm text-destructive"
              role="alert"
              data-testid="hunt-triage-error"
            >
              {error}
            </div>
          )}

          {isLoading && clusters.length === 0 && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading hunt inbox…
            </div>
          )}

          {!isLoading && filteredClusters.length === 0 && (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Crosshair className="mx-auto mb-3 h-8 w-8 opacity-30" />
                <p className="text-sm">
                  {activeTab === "active" && "No active hunt findings."}
                  {activeTab === "suppressed" && "No suppressed findings."}
                  {activeTab === "promoted" && "No promoted findings."}
                </p>
                {activeTab === "active" && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Findings from hunt packs, behavioral and identity hunts will cluster here.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {filteredClusters.map((c) => (
            <ClusterCard
              key={c.id}
              cluster={c}
              findings={byCluster[c.id] ?? []}
              selected={selectedFindingIds}
              onToggle={toggleSelected}
              onSuppressFinding={(f) => setSuppressTarget({ kind: "finding", finding: f })}
              onPromoteFinding={(f) => setPromoteTarget({ kind: "finding", finding: f })}
              onSuppressCluster={(cl) => setSuppressTarget({ kind: "cluster", cluster: cl })}
              onPromoteCluster={(cl) => setPromoteTarget({ kind: "cluster", cluster: cl })}
              canTriage={canTriage}
            />
          ))}

          <Pagination
            page={page}
            totalClusters={totalClusters}
            pageSize={pageSize}
            onPage={setPage}
          />
        </div>
      </div>

      {/* ---- Bulk promote action bar ---- */}
      {selectedFindingIds.length > 0 && canTriage && (
        <div
          className="flex items-center justify-between gap-4 px-6 py-3 border-t border-border bg-background"
          data-testid="hunt-promote-bar"
        >
          <span className="text-sm text-muted-foreground">
            {selectedFindingIds.length} finding
            {selectedFindingIds.length === 1 ? "" : "s"} selected
          </span>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={clearSelection}>
              Clear
            </Button>
            <Button
              onClick={() => { void handleBulkPromote(); }}
              disabled={isMutating}
              data-testid="hunt-promote-submit"
            >
              <ArrowUpRight className="w-4 h-4 mr-2" />
              Promote to investigation
            </Button>
          </div>
        </div>
      )}

      {/* ---- Modals ---- */}
      <SuppressModal
        target={suppressTarget}
        onClose={() => setSuppressTarget(null)}
      />
      <PromoteModal
        target={promoteTarget}
        onClose={() => setPromoteTarget(null)}
      />
    </div>
  );
}
