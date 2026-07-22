/**
 * Noisy Rules advisory panel (#112).
 *
 * Surfaces `GET /hunt/noise-baseline` — pack rules that hit on (nearly)
 * every run and are therefore matching baseline activity, not incidents.
 * Advisory only: nothing here suppresses. The analyst reviews the list and
 * acts through the existing suppress actions on the findings below.
 *
 * Renders nothing when the baseline is empty or fails to load — a quiet
 * environment shouldn't pay a UI tax for the analysis.
 */

import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Loader2, RefreshCw, VolumeX } from "lucide-react";
import { Card, CardContent } from "@/components/ds/card";
import { Button } from "@/components/ds/button";
import { getNoiseBaseline } from "@/api/hunt";
import type { NoiseBaseline } from "@/types/hunt";

export function NoisyRulesPanel() {
  const [baseline, setBaseline] = useState<NoiseBaseline | null>(null);
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const refresh = useCallback(async () => {
    setIsLoading(true);
    try {
      setBaseline(await getNoiseBaseline());
    } catch {
      /* advisory surface — stay silent on failure */
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (!baseline || baseline.items.length === 0) return null;

  return (
    <Card data-testid="noisy-rules-panel">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-2 text-sm font-medium text-foreground"
            data-testid="noisy-rules-toggle"
          >
            {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            <VolumeX className="w-4 h-4 text-amber-400" aria-hidden="true" />
            Noisy rules ({baseline.items.length})
          </button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void refresh()}
            disabled={isLoading}
            data-testid="noisy-rules-refresh"
            title="Re-run the noise-baseline analysis"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
          </Button>
        </div>

        {open && (
          <div className="mt-3 space-y-2">
            <p className="text-xs text-muted-foreground">
              These pack rules hit on nearly every run over the last{" "}
              {baseline.runs_analyzed} run{baseline.runs_analyzed === 1 ? "" : "s"} — likely
              baseline activity. Review and suppress via the findings below; nothing is
              suppressed automatically.
            </p>
            {baseline.items.map((r) => (
              <div
                key={`${r.pack_id}:${r.rule_id}`}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/60 bg-muted/20 px-3 py-2"
                data-testid={`noisy-rule-${r.rule_id}`}
              >
                <div className="min-w-0">
                  <p className="truncate text-sm text-foreground">{r.rule_title}</p>
                  <p className="text-xs text-muted-foreground">{r.pack_name}</p>
                </div>
                <div className="flex shrink-0 items-center gap-2 text-xs">
                  <span
                    className="rounded border border-amber-500/30 bg-amber-600/20 px-1.5 py-0.5 text-amber-300"
                    data-testid={`noisy-rule-rate-${r.rule_id}`}
                  >
                    hit {Math.round(r.hit_rate * 100)}% of {r.runs_observed} runs
                  </span>
                  <span className="text-muted-foreground">
                    {r.total_hits} hit{r.total_hits === 1 ? "" : "s"} total
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
