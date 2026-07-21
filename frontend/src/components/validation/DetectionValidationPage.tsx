/**
 * Detection Validation page (#118).
 *
 * A read-only coverage-history view for the detection-validation runs persisted
 * by the backend (``detection_validation_runs``). Analysts trigger a run
 * (``POST /validation/runs``) and watch detection coverage over time
 * (``GET /validation/runs``): overall detected %, techniques exercised, and the
 * gap list (techniques with at least one missed expected-to-fire event).
 *
 * Mock-first: the backend replays a deterministic synthetic scenario set until
 * live Atomic Red Team / Caldera execution is wired. RBAC is enforced
 * server-side (hunt:run to trigger, hunt:view to read).
 */

import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, Loader2, RefreshCw, Play } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { listValidationRuns, runValidation } from "@/api/validation";
import type { ValidationRunSummary } from "@/types/validation";

function formatPct(pct: number): string {
  return `${Math.round(pct)}%`;
}

function coverageColor(pct: number): string {
  if (pct >= 80) return "text-emerald-400";
  if (pct >= 50) return "text-amber-400";
  return "text-rose-400";
}

export function DetectionValidationPage() {
  const [runs, setRuns] = useState<ValidationRunSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchRuns = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await listValidationRuns();
      setRuns(resp.items);
      setTotal(resp.total);
    } catch {
      setError("Failed to load validation runs.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchRuns();
  }, [fetchRuns]);

  const handleRun = useCallback(async () => {
    setIsRunning(true);
    setError(null);
    try {
      await runValidation();
      await fetchRuns();
    } catch {
      setError("Validation run failed.");
    } finally {
      setIsRunning(false);
    }
  }, [fetchRuns]);

  return (
    <div className="flex flex-col h-full" data-testid="detection-validation">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-emerald-600/20 border border-emerald-500/30">
            <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">Detection Validation</h1>
            <p className="text-sm text-muted-foreground">
              {total} run{total === 1 ? "" : "s"} · coverage over time
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void fetchRuns()}
            disabled={isLoading}
            data-testid="validation-refresh"
            title="Refresh the run history"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleRun()}
            disabled={isRunning}
            data-testid="validation-run"
            title="Replay the built-in scenarios and land a fresh coverage report"
          >
            {isRunning ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span className="ml-2 hidden sm:inline">Run validation</span>
          </Button>
        </div>
      </div>

      {/* ---- Body ---- */}
      <div className="flex-1 overflow-auto p-6">
        {error && (
          <div
            className="mb-4 rounded-md border border-rose-500/30 bg-rose-600/10 px-4 py-2 text-sm text-rose-300"
            data-testid="validation-error"
          >
            {error}
          </div>
        )}

        {runs.length === 0 && !isLoading ? (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              No validation runs yet. Trigger one with “Run validation”.
            </CardContent>
          </Card>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm" data-testid="validation-runs-table">
              <thead>
                <tr className="text-left text-muted-foreground border-b border-border">
                  <th className="py-2 pr-4 font-medium">Run</th>
                  <th className="py-2 pr-4 font-medium">Coverage</th>
                  <th className="py-2 pr-4 font-medium">Techniques</th>
                  <th className="py-2 pr-4 font-medium">Gaps</th>
                  <th className="py-2 pr-4 font-medium">When</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr
                    key={run.id}
                    className="border-b border-border/50"
                    data-testid={`validation-run-${run.id}`}
                  >
                    <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">
                      {run.run_id}
                    </td>
                    <td className={`py-2 pr-4 font-semibold ${coverageColor(run.detected_pct)}`}>
                      {formatPct(run.detected_pct)}
                    </td>
                    <td className="py-2 pr-4">{run.total_techniques}</td>
                    <td className="py-2 pr-4">
                      {run.gaps.length === 0 ? (
                        <span className="text-emerald-400">none</span>
                      ) : (
                        <span className="text-rose-300">{run.gaps.join(", ")}</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 text-muted-foreground">
                      {new Date(run.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
