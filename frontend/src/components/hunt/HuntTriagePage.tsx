import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Crosshair, ShieldOff, ArrowUpRight, RefreshCw, Eye, EyeOff } from "lucide-react";
import { Severity as ConfigSeverity } from "@/types/config";
import { SeverityBadge } from "@/components/ui/Badge";
import type { HuntFinding, HuntFindingCluster } from "@/types/hunt";
import { useHuntStore, groupFindingsByCluster } from "@/stores/huntStore";
import { SuppressModal } from "./SuppressModal";

function sev(s: string): ConfigSeverity {
  return s as ConfigSeverity;
}

function ClusterCard({
  cluster,
  findings,
  selected,
  onToggle,
  onSuppress,
}: {
  cluster: HuntFindingCluster;
  findings: HuntFinding[];
  selected: string[];
  onToggle: (id: string) => void;
  onSuppress: (f: HuntFinding) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="rounded-lg border border-slate-700/50 bg-slate-800/40"
      data-testid="hunt-cluster-card"
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <SeverityBadge severity={sev(cluster.severity)} />
          <span className="truncate text-sm font-medium text-slate-100">{cluster.title}</span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex flex-wrap gap-1">
            {cluster.technique_ids.slice(0, 4).map((t) => (
              <span
                key={t}
                className="px-1.5 py-0.5 rounded text-[11px] bg-blue-500/10 text-blue-300 border border-blue-500/20"
              >
                {t}
              </span>
            ))}
          </div>
          <span className="text-xs text-slate-400" data-testid="hunt-cluster-count">
            {cluster.finding_count} finding{cluster.finding_count === 1 ? "" : "s"}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-slate-700/50">
          {findings.length === 0 && (
            <p className="px-4 py-3 text-xs text-slate-500">No visible findings in this cluster.</p>
          )}
          {findings.map((f) => (
            <div
              key={f.id}
              className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-slate-800 last:border-0"
              data-testid="hunt-finding-row"
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
                <button
                  onClick={() => onSuppress(f)}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-slate-400 hover:text-amber-300"
                  data-testid="hunt-finding-suppress"
                >
                  <ShieldOff className="w-3.5 h-3.5" />
                  Suppress
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function HuntTriagePage() {
  const navigate = useNavigate();
  const {
    clusters,
    findings,
    totalClusters,
    totalFindings,
    includeSuppressed,
    isLoading,
    isMutating,
    error,
    selectedFindingIds,
    fetchInbox,
    toggleIncludeSuppressed,
    toggleSelected,
    clearSelection,
    promote,
  } = useHuntStore();

  const [suppressTarget, setSuppressTarget] = useState<HuntFinding | null>(null);

  useEffect(() => {
    void fetchInbox();
  }, [fetchInbox]);

  const byCluster = useMemo(() => groupFindingsByCluster(findings), [findings]);

  const handlePromote = async () => {
    if (selectedFindingIds.length === 0) return;
    const invId = await promote(selectedFindingIds);
    navigate(`/investigations/${invId}`);
  };

  return (
    <div className="flex flex-col h-full" data-testid="hunt-triage">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-rose-600/20 border border-rose-500/30">
            <Crosshair className="w-4 h-4 text-rose-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-slate-100">Hunt Triage</h1>
            <p className="text-sm text-slate-400">
              {totalClusters} cluster{totalClusters === 1 ? "" : "s"} · {totalFindings} finding
              {totalFindings === 1 ? "" : "s"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void toggleIncludeSuppressed()}
            className="flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-slate-100 border border-slate-700 rounded-lg"
            data-testid="hunt-toggle-suppressed"
          >
            {includeSuppressed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {includeSuppressed ? "Hide suppressed" : "Show suppressed"}
          </button>
          <button
            onClick={() => void fetchInbox()}
            className="flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:text-slate-100 border border-slate-700 rounded-lg"
            data-testid="hunt-refresh"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-3">
          {error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          {isLoading && clusters.length === 0 && (
            <p className="text-sm text-slate-500">Loading hunt inbox…</p>
          )}

          {!isLoading && clusters.length === 0 && (
            <div className="rounded-lg border border-slate-700/50 bg-slate-800/40 px-6 py-12 text-center">
              <Crosshair className="mx-auto mb-3 h-8 w-8 text-slate-600" />
              <p className="text-sm text-slate-400">No hunt findings yet.</p>
              <p className="text-xs text-slate-500">
                Findings from hunt packs, behavioral and identity hunts will cluster here.
              </p>
            </div>
          )}

          {clusters.map((c) => (
            <ClusterCard
              key={c.id}
              cluster={c}
              findings={byCluster[c.id] ?? []}
              selected={selectedFindingIds}
              onToggle={toggleSelected}
              onSuppress={setSuppressTarget}
            />
          ))}
        </div>
      </div>

      {/* Promote action bar */}
      {selectedFindingIds.length > 0 && (
        <div
          className="flex items-center justify-between gap-4 px-6 py-3 border-t border-slate-700/50 bg-slate-900"
          data-testid="hunt-promote-bar"
        >
          <span className="text-sm text-slate-300">
            {selectedFindingIds.length} finding{selectedFindingIds.length === 1 ? "" : "s"} selected
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={clearSelection}
              className="px-3 py-2 text-sm text-slate-400 hover:text-slate-200"
            >
              Clear
            </button>
            <button
              onClick={() => void handlePromote()}
              disabled={isMutating}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
              data-testid="hunt-promote-submit"
            >
              <ArrowUpRight className="w-4 h-4" />
              Promote to investigation
            </button>
          </div>
        </div>
      )}

      <SuppressModal finding={suppressTarget} onClose={() => setSuppressTarget(null)} />
    </div>
  );
}
