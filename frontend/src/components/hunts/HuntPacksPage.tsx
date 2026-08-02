/**
 * Hunt Packs — Phase B view (#112). Distinct from ``HuntPackagePage`` (the
 * advisory-driven, one-shot hunt *package* builder): this screen is the
 * operational surface for the *scheduled hunt-pack runner*.
 *
 * Layout
 * ------
 * - Installed-packs list (``GET /hunt/packs`` joined with the run history from
 *   ``GET /hunt/pack-runs``): name + version + backends, an enable/disable
 *   switch wired to the **per-org pack store** (``PUT /hunt/packs/{key}``,
 *   RBAC ``huntpack:manage``), the last-run status, and a 30-day hit-volume
 *   sparkline. Packs that ship but have never run are listed too — otherwise
 *   there would be no way to turn one on.
 * - Per-rule status grid: one chip per rule coloured by its
 *   :type:`HuntRuleState` (clean / firing_as_expected / over_firing /
 *   under_firing / errored), derived from the run history + the noise baseline
 *   (``GET /hunt/noise-baseline``).
 * - Rule detail: the selected rule's per-backend transpiled queries.
 *
 * The installed-pack list and rule grid are read-only + advisory and poll
 * every 30s (same cadence as the other Phase-B hunt screens). The suggestion
 * inbox at the top is the one exception: accepting or dismissing a suggested
 * pack writes, and is gated on ``hunt:promote``.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Loader2,
  Package,
  RefreshCw,
  Terminal,
  ToggleLeft,
  ToggleRight,
  X,
} from "lucide-react";
import { PackSuggestionsPanel } from "./PackSuggestionsPanel";
import { CustomPacksPanel } from "./CustomPacksPanel";
import {
  useHuntPacksStore,
  buildInstalledPacks,
  type HitVolumePoint,
  type InstalledPack,
  type RuleStatus,
} from "@/stores/huntPacksStore";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import type { HuntRuleState } from "@/types/hunt";

const POLL_INTERVAL_MS = 30_000;

// ---------------------------------------------------------------------------
// RBAC — mirrors the backend gate: viewing the catalog is ``hunt:view``, while
// flipping a pack is ``huntpack:manage`` (senior_analyst+). This only hides the
// affordance; the server re-checks and 403s regardless.
// ---------------------------------------------------------------------------

function useCanManage(): boolean {
  const role = useAuthStore((s) => s.user?.role);
  return (
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN
  );
}

// ---------------------------------------------------------------------------
// Rule-state + run-status presentation
// ---------------------------------------------------------------------------

const RULE_STATE_STYLE: Record<HuntRuleState, { label: string; cls: string }> = {
  clean: { label: "Clean", cls: "bg-slate-500/20 text-slate-300 border-slate-500/30" },
  firing_as_expected: {
    label: "Firing as expected",
    cls: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  },
  over_firing: {
    label: "Over-firing",
    cls: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  },
  under_firing: {
    label: "Under-firing",
    cls: "bg-sky-500/20 text-sky-300 border-sky-500/30",
  },
  errored: { label: "Errored", cls: "bg-rose-500/20 text-rose-300 border-rose-500/30" },
};

const RUN_STATUS_STYLE: Record<string, string> = {
  completed: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  completed_with_errors: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  running: "bg-sky-500/20 text-sky-300 border-sky-500/30",
  failed: "bg-rose-500/20 text-rose-300 border-rose-500/30",
};

function RuleStateChip({ state }: { state: HuntRuleState }) {
  const s = RULE_STATE_STYLE[state];
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${s.cls}`}>
      {s.label}
    </span>
  );
}

function RunStatusBadge({ status }: { status: string }) {
  const cls = RUN_STATUS_STYLE[status] ?? RUN_STATUS_STYLE["completed"];
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${cls}`}
      data-testid="run-status-badge"
    >
      {status.replace(/_/g, " ")}
    </span>
  );
}

/**
 * E7: the last sweep was stopped early by the rules-per-sweep cap or the
 * per-run deadline.
 *
 * A truncated run still reports ``completed``, so the status badge alone reads
 * as a clean sweep. That is the misreading worth preventing: "0 hits" on a
 * capped run means "we did not look at every rule", not "nothing is there".
 */
function PartialSweepBadge({ count }: { count: number }) {
  return (
    <span
      className="flex items-center gap-1 rounded border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-medium text-amber-300"
      data-testid="run-truncated-badge"
      title={
        count > 0
          ? `Stopped early by the rule cap or run deadline — ${count} rule${count === 1 ? "" : "s"} never ran. Hit counts do not cover the whole pack.`
          : "Stopped early by the rule cap or run deadline. Hit counts do not cover the whole pack."
      }
    >
      <AlertTriangle className="h-3 w-3" aria-hidden="true" />
      partial sweep{count > 0 ? ` (${count} not run)` : ""}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Sparkline — inline SVG, no external chart dep (CSP-safe).
// ---------------------------------------------------------------------------

function Sparkline({ points }: { points: HitVolumePoint[] }) {
  const width = 160;
  const height = 32;
  const max = Math.max(1, ...points.map((p) => p.hits));
  const step = points.length > 1 ? width / (points.length - 1) : width;
  const coords = points
    .map((p, i) => {
      const x = i * step;
      const y = height - (p.hits / max) * (height - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const total = points.reduce((sum, p) => sum + p.hits, 0);
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      role="img"
      aria-label={`30-day hit volume, ${total} hits total`}
      data-testid="hitvol-sparkline"
      className="overflow-visible"
    >
      <polyline
        points={coords}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        className="text-primary"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Rule detail — per-backend transpiled queries
// ---------------------------------------------------------------------------

function RuleDetail({ rule, onClose }: { rule: RuleStatus; onClose: () => void }) {
  const backends = Object.keys(rule.queries);
  return (
    <Card data-testid="rule-detail">
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-foreground">{rule.title}</p>
            <p className="font-mono text-[11px] text-muted-foreground">{rule.rule_id}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <RuleStateChip state={rule.state} />
            <button
              type="button"
              onClick={onClose}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Close rule detail"
              data-testid="rule-detail-close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
          <span>
            last hits: <span className="text-foreground">{rule.last_hits}</span>
          </span>
          <span>
            observed: <span className="text-foreground">{rule.runs_observed}</span> runs
          </span>
          <span>
            hit rate: <span className="text-foreground">{Math.round(rule.hit_rate * 100)}%</span>
          </span>
          {rule.last_errors > 0 && (
            <span className="text-rose-300">errors: {rule.last_errors}</span>
          )}
        </div>

        <div className="space-y-2">
          <p className="flex items-center gap-1.5 text-xs font-medium text-foreground">
            <Terminal className="h-3.5 w-3.5" />
            Transpiled queries
          </p>
          {backends.length === 0 ? (
            <p className="text-xs text-muted-foreground" data-testid="rule-detail-no-queries">
              No transpiled query captured for this rule's last run.
            </p>
          ) : (
            backends.map((backend) => (
              <div key={backend} data-testid={`rule-query-${backend}`}>
                <p className="text-[11px] uppercase tracking-wide text-muted-foreground">
                  {backend}
                </p>
                <pre className="overflow-x-auto rounded bg-muted/40 px-2 py-1.5 font-mono text-[11px] text-foreground">
                  {rule.queries[backend]}
                </pre>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Installed pack card
// ---------------------------------------------------------------------------

function PackCard({
  pack,
  canManage,
  isToggling,
  selectedRuleId,
  onToggle,
  onSelectRule,
}: {
  pack: InstalledPack;
  canManage: boolean;
  isToggling: boolean;
  selectedRuleId: string | null;
  onToggle: () => void;
  onSelectRule: (ruleId: string) => void;
}) {
  const disabled = !pack.enabled;
  const lastRunAt = pack.last_run?.started_at
    ? new Date(pack.last_run.started_at).toLocaleString()
    : "never";
  const ruleCount = pack.rules.length || pack.rule_count;
  // Two inert-switch cases: an ad-hoc pack (run history, no catalog entry)
  // is not schedulable at all; a "custom" uploaded bundle IS scheduled but is
  // enabled by existence — its lifecycle is the custom-packs panel below, not
  // the toggle API (which would 404 on its id).
  const canToggle =
    canManage && pack.install_key !== null && pack.source !== "custom" && !isToggling;
  return (
    <Card data-testid={`pack-card-${pack.pack_id}`} className={disabled ? "opacity-60" : ""}>
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Package className="h-4 w-4 text-primary" />
              <span className="truncate">{pack.pack_name}</span>
              <span className="rounded bg-muted/50 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                v{pack.pack_version || "?"}
              </span>
              {pack.source === "custom" && (
                <span
                  className="rounded bg-primary/15 px-1.5 py-0.5 text-[11px] text-primary"
                  data-testid={`pack-custom-badge-${pack.pack_id}`}
                >
                  custom
                </span>
              )}
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {ruleCount} rule{ruleCount === 1 ? "" : "s"} ·{" "}
              {pack.backends.join(", ") || "no backends"} · {pack.run_count} run
              {pack.run_count === 1 ? "" : "s"}
            </p>
          </div>
          <button
            type="button"
            onClick={onToggle}
            disabled={!canToggle}
            className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground enabled:hover:text-foreground disabled:cursor-not-allowed"
            data-testid={`pack-toggle-${pack.pack_id}`}
            title={
              pack.install_key === null
                ? "Ad-hoc pack — not part of the scheduled catalog"
                : pack.source === "custom"
                  ? "Org custom pack — runs on every sweep while uploaded; manage it in the Custom packs panel"
                  : canManage
                    ? "Enable/disable this pack for your organization"
                    : "Enable/disable requires senior_analyst or higher"
            }
          >
            {isToggling ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : disabled ? (
              <ToggleLeft className="h-5 w-5" />
            ) : (
              <ToggleRight className="h-5 w-5 text-emerald-400" />
            )}
            {disabled ? "Disabled" : "Enabled"}
          </button>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Activity className="h-3.5 w-3.5" />
            last run: <span className="text-foreground">{lastRunAt}</span>
            {pack.last_run && <RunStatusBadge status={pack.last_run.status} />}
            {pack.last_run?.truncated && (
              <PartialSweepBadge count={pack.last_run.rules_not_run?.length ?? 0} />
            )}
          </div>
          <div className="text-primary">
            <Sparkline points={pack.hit_volume_30d} />
          </div>
        </div>

        <div>
          <p className="mb-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
            Rule status
          </p>
          <div className="flex flex-wrap gap-1.5" data-testid={`rule-grid-${pack.pack_id}`}>
            {pack.rules.map((rule) => {
              const s = RULE_STATE_STYLE[rule.state];
              const isSel = rule.rule_id === selectedRuleId;
              return (
                <button
                  key={rule.rule_id}
                  type="button"
                  onClick={() => onSelectRule(rule.rule_id)}
                  className={`max-w-[16rem] truncate rounded border px-2 py-1 text-[11px] font-medium ${s.cls} ${
                    isSel ? "ring-2 ring-primary" : ""
                  }`}
                  data-testid={`rule-chip-${rule.rule_id}`}
                  title={`${rule.title} — ${s.label}`}
                >
                  {rule.state === "errored" && (
                    <AlertTriangle className="mr-1 inline h-3 w-3" aria-hidden="true" />
                  )}
                  {rule.title}
                </button>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function HuntPacksPage() {
  const runs = useHuntPacksStore((s) => s.runs);
  const baseline = useHuntPacksStore((s) => s.baseline);
  const catalog = useHuntPacksStore((s) => s.catalog);
  const togglingPackId = useHuntPacksStore((s) => s.togglingPackId);
  const selectedRuleId = useHuntPacksStore((s) => s.selectedRuleId);
  const isLoading = useHuntPacksStore((s) => s.isLoading);
  const error = useHuntPacksStore((s) => s.error);
  const fetchAll = useHuntPacksStore((s) => s.fetchAll);
  const togglePackEnabled = useHuntPacksStore((s) => s.togglePackEnabled);
  const selectRule = useHuntPacksStore((s) => s.selectRule);

  const canManage = useCanManage();
  const [hasLoadedOnce, setHasLoadedOnce] = useState(false);

  const refresh = useCallback(async () => {
    await fetchAll();
    setHasLoadedOnce(true);
  }, [fetchAll]);

  // Poll on mount + every 30s.
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    void refresh();
    timer.current = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [refresh]);

  const packs = useMemo(
    () => buildInstalledPacks(runs, baseline, catalog),
    [runs, baseline, catalog],
  );

  const selectedRule = useMemo<RuleStatus | null>(() => {
    if (!selectedRuleId) return null;
    for (const pack of packs) {
      const rule = pack.rules.find((r) => r.rule_id === selectedRuleId);
      if (rule) return rule;
    }
    return null;
  }, [packs, selectedRuleId]);

  return (
    <div className="flex-1 space-y-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-semibold text-foreground">
            <Package className="h-5 w-5 text-primary" />
            Hunt Packs
          </h1>
          <p className="text-sm text-muted-foreground">
            Installed hunt packs, per-rule health, and 30-day hit volume from the scheduled
            runner.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void refresh()}
          disabled={isLoading}
          data-testid="huntpacks-refresh"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <RefreshCw className="h-4 w-4" />
          )}
          <span className="ml-1">Refresh</span>
        </Button>
      </div>

      {error && (
        <Card>
          <CardContent className="flex items-center gap-2 p-4 text-sm text-rose-300">
            <AlertTriangle className="h-4 w-4" />
            <span data-testid="huntpacks-error">{error}</span>
          </CardContent>
        </Card>
      )}

      {/* Suggestion inbox (#120/#112) — accepted suggestions become the
       * installed packs listed below, so the queue belongs above them.
       * Hides itself if its fetch fails; it's advisory, not a dependency. */}
      <PackSuggestionsPanel />

      {/* Org-custom pack bundles (#112 slice 2) */}
      <CustomPacksPanel />

      {selectedRule && (
        <RuleDetail rule={selectedRule} onClose={() => selectRule(null)} />
      )}

      {hasLoadedOnce && packs.length === 0 && !error ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            No hunt-pack runs yet. The scheduled runner will populate this view on its next
            sweep.
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {packs.map((pack) => (
            <PackCard
              key={pack.pack_id}
              pack={pack}
              canManage={canManage}
              isToggling={
                pack.install_key !== null && togglingPackId === pack.install_key
              }
              selectedRuleId={selectedRuleId}
              onToggle={() => void togglePackEnabled(pack.install_key, !pack.enabled)}
              onSelectRule={(ruleId) =>
                selectRule(ruleId === selectedRuleId ? null : ruleId)
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}
