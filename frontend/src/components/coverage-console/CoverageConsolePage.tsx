/**
 * Coverage Console (#501) — the detection-engineering loop on one screen.
 *
 * Bet 1 (#98) was ~80% built and 100% invisible: coverage freshness lived in
 * `/validation/coverage-map`, rule health in the noise baseline, drafts in the
 * proposal queue, and the ATT&CK view in the matrix — four screens, no story.
 * This page composes the single `GET /coverage/console` payload into that
 * story: *what do we detect, what is broken, what is unproven, what next.*
 *
 * It computes nothing. Every band, state and ranking is read off the server
 * response, so the console can never disagree with the surfaces it links to.
 *
 * Directory name: `coverage-console/`, not `coverage/` — the repo's root
 * `.gitignore` excludes `coverage/` (test-coverage reports), which would
 * silently swallow this whole directory.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { Gauge, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Skeleton } from "@/components/ds/skeleton";
import { getCoverageConsole } from "@/api/coverage";
import { BrokenRulesPanel } from "./BrokenRulesPanel";
import { CoverageHeatmap } from "./CoverageHeatmap";
import { NextBestActionsPanel } from "./NextBestActionsPanel";
import { TelemetryGapsPanel } from "./TelemetryGapsPanel";
import { STATUS_LABEL, ageLabel } from "./coverage-format";
import type { CoverageConsole, TechniqueCoverageCell } from "@/types/coverage";
import type { ValidationVerdictKind } from "@/types/validation";

const VERDICT_ORDER: ValidationVerdictKind[] = [
  "validated",
  "wrong_severity",
  "late",
  "silent_gap",
  "errored",
];

const VERDICT_STYLE: Record<ValidationVerdictKind, string> = {
  validated: "text-emerald-400",
  wrong_severity: "text-amber-400",
  late: "text-amber-400",
  silent_gap: "text-rose-400",
  errored: "text-rose-400",
};

function Tile({
  label,
  value,
  tone = "",
  testId,
}: {
  label: string;
  value: number | string;
  tone?: string;
  testId: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card/50 px-3 py-2" data-testid={testId}>
      <p className={`text-lg font-semibold ${tone}`}>{value}</p>
      <p className="text-[11px] text-muted-foreground">{label}</p>
    </div>
  );
}

export function CoverageConsolePage() {
  const [console_, setConsole] = useState<CoverageConsole | null>(null);
  const [staleDays, setStaleDays] = useState(90);
  const [daysInput, setDaysInput] = useState("90");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  const load = useCallback(async (days: number) => {
    setLoading(true);
    setError(null);
    try {
      setConsole(await getCoverageConsole({ staleDays: days }));
    } catch {
      // An empty console reads as "everything is fine", which is the single
      // most dangerous way for this page to fail.
      setError("Could not load the coverage console.");
      setConsole(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(staleDays);
  }, [load, staleDays]);

  const selectedCell: TechniqueCoverageCell | null = useMemo(() => {
    if (!selected || !console_) return null;
    return console_.techniques.find((t) => t.technique_id === selected) ?? null;
  }, [selected, console_]);

  const summary = console_?.summary;

  return (
    <div className="flex h-full flex-col" data-testid="coverage-console">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-primary/30 bg-primary/20">
            <Gauge className="h-4 w-4 text-primary" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Coverage Console</h1>
            <p className="text-sm text-muted-foreground">
              What we detect, what is broken, what is unproven — and what to do next.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <form
            className="flex items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              const n = Number(daysInput);
              // Mirrors the server bound (ge=1, le=3650); out-of-range would
              // 422 and read as a broken page.
              if (Number.isFinite(n) && n >= 1 && n <= 3650) setStaleDays(Math.floor(n));
            }}
          >
            <label className="text-xs text-muted-foreground" htmlFor="coverage-stale-days">
              Stale after
            </label>
            <Input
              id="coverage-stale-days"
              value={daysInput}
              onChange={(e) => setDaysInput(e.target.value)}
              aria-label="Stale after (days)"
              data-testid="coverage-stale-days"
              className="h-8 w-20"
            />
            <Button type="submit" size="sm" variant="ghost" data-testid="coverage-apply">
              Apply
            </Button>
          </form>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void load(staleDays)}
            disabled={loading}
            data-testid="coverage-refresh"
            title="Reload the console"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>

      {/* ---- Body ---- */}
      <div className="flex-1 space-y-4 overflow-auto p-6">
        {error && (
          <div
            className="rounded-md border border-rose-500/30 bg-rose-600/10 px-4 py-2 text-sm text-rose-300"
            data-testid="coverage-console-error"
            role="alert"
          >
            {error}
          </div>
        )}

        {console_ === null && !error ? (
          <div className="space-y-3" data-testid="coverage-console-loading">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-48 w-full" />
          </div>
        ) : null}

        {console_ && summary && (
          <>
            {/* ---- Summary tiles ---- */}
            <div
              className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
              data-testid="coverage-summary"
            >
              <Tile
                label="techniques tracked"
                value={summary.total_techniques}
                testId="coverage-tile-total"
              />
              <Tile
                label="validated recently"
                value={summary.fresh}
                tone="text-emerald-400"
                testId="coverage-tile-fresh"
              />
              <Tile
                label={`stale (>${console_.stale_days}d)`}
                value={summary.stale}
                tone="text-amber-400"
                testId="coverage-tile-stale"
              />
              <Tile
                label="never validated"
                value={summary.never_validated}
                tone="text-rose-400"
                testId="coverage-tile-never"
              />
              <Tile
                label="silent gaps"
                value={summary.silent_gap}
                tone="text-rose-400"
                testId="coverage-tile-silent-gap"
              />
              <Tile
                label="broken rules"
                value={summary.broken_rules}
                tone={summary.broken_rules > 0 ? "text-amber-400" : ""}
                testId="coverage-tile-broken"
              />
            </div>

            {/* ---- Pipeline + matrix context ---- */}
            <div
              className="flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card/30 px-4 py-2 text-xs text-muted-foreground"
              data-testid="coverage-context"
            >
              <span data-testid="coverage-context-mapped">
                <span className="font-semibold text-foreground">
                  {summary.mapped_techniques}
                </span>{" "}
                mapped of {summary.mitre_total_techniques} ATT&CK techniques ·{" "}
                <span className="text-amber-400">{summary.unmapped_techniques}</span> unmapped
              </span>
              <span data-testid="coverage-context-proposals">
                <Link to="/detection-proposals" className="text-primary hover:underline">
                  {summary.proposals_awaiting_review} draft(s) awaiting review
                </Link>{" "}
                · {summary.prs_open} PR(s) open
              </span>
              <span className="ml-auto" data-testid="coverage-verdicts">
                {VERDICT_ORDER.map((kind) => (
                  <span key={kind} className="ml-3">
                    <span className={VERDICT_STYLE[kind]}>{console_.verdict_counts[kind]}</span>{" "}
                    {kind.replace(/_/g, " ")}
                  </span>
                ))}
              </span>
            </div>

            {/* ---- Next best actions ---- */}
            <NextBestActionsPanel actions={console_.next_best_actions} />

            {/* ---- Heatmap ---- */}
            <CoverageHeatmap tactics={console_.tactics} onSelectTechnique={setSelected} />

            {selectedCell && (
              <div
                className="flex flex-wrap items-center gap-3 rounded-lg border border-primary/40 bg-primary/5 px-4 py-2 text-xs"
                data-testid="coverage-selected"
              >
                <span className="font-mono">{selectedCell.technique_id}</span>
                {selectedCell.name && (
                  <span className="text-muted-foreground">{selectedCell.name}</span>
                )}
                <span data-testid="coverage-selected-status">
                  {STATUS_LABEL[selectedCell.status]} · {ageLabel(selectedCell)}
                </span>
                <Link
                  to="/detection-validation"
                  className="ml-auto text-primary hover:underline"
                  data-testid="coverage-selected-validate"
                >
                  Validate →
                </Link>
                <Link
                  to="/detection-proposals"
                  className="text-primary hover:underline"
                  data-testid="coverage-selected-propose"
                >
                  Detections →
                </Link>
                <Link
                  to="/mitre"
                  className="text-primary hover:underline"
                  data-testid="coverage-selected-matrix"
                >
                  ATT&CK →
                </Link>
              </div>
            )}

            {/* ---- Broken rules + telemetry gaps ---- */}
            <div className="grid gap-4 lg:grid-cols-2">
              <BrokenRulesPanel rules={console_.broken_rules} />
              <TelemetryGapsPanel gaps={console_.telemetry_gaps} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
