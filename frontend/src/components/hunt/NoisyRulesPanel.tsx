/**
 * Noisy Rules advisory panel (#112).
 *
 * Surfaces `GET /hunt/noise-baseline` — pack rules that hit on (nearly)
 * every run and are therefore matching baseline activity, not incidents.
 * Seniors (`canSuppress`) get a one-click "Suppress rule" per row that
 * creates a rule_ids-targeted suppression (mutes exactly that detection
 * rule, pre-filled name/reason from the baseline stats); analysts see the
 * advisory list only. The decision stays human — nothing auto-suppresses.
 *
 * It also carries the payload's `never_run` list: enabled rules the
 * rules-per-sweep cap or the per-run deadline skipped on *every* sweep in the
 * window. Those have no hit statistics at all, so no amount of reading the
 * noisy or under-firing lists would reveal them — the pack simply looks like
 * it is covering ground it has never touched. There is no one-click action:
 * the fix is raising a cap or splitting a pack, which is a schedule decision,
 * not a suppression.
 *
 * Renders nothing when both lists are empty or the fetch fails — a quiet
 * environment shouldn't pay a UI tax for the analysis.
 */

import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, EyeOff, Loader2, RefreshCw, VolumeX } from "lucide-react";
import { Card, CardContent } from "@/components/ds/card";
import { Button } from "@/components/ds/button";
import { createSuppression, getNoiseBaseline } from "@/api/hunt";
import type { NoiseBaseline, NoisyRule } from "@/types/hunt";

export function NoisyRulesPanel({
  canSuppress = false,
  onSuppressed,
}: {
  canSuppress?: boolean;
  /** Called after a suppression lands — the parent refreshes its inbox,
   *  since the backend suppresses existing matching findings immediately. */
  onSuppressed?: () => void;
}) {
  const [baseline, setBaseline] = useState<NoiseBaseline | null>(null);
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [suppressingId, setSuppressingId] = useState<string | null>(null);
  const [mutedRuleIds, setMutedRuleIds] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

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

  const handleSuppress = useCallback(
    async (r: NoisyRule) => {
      setSuppressingId(r.rule_id);
      setError(null);
      try {
        await createSuppression({
          name: `Mute noisy rule: ${r.rule_title}`.slice(0, 200),
          reason:
            `Noise baseline: hit ${Math.round(r.hit_rate * 100)}% of ` +
            `${r.runs_observed} runs (${r.total_hits} hits total).`,
          match: {
            // Scoped to pack findings: identity hunts reuse detector ids in
            // evidence.rule_id, so a bare rule_ids match could over-suppress
            // (Codex review on #324).
            source: "hunt_pack",
            domain: "sigma",
            technique_ids: [],
            entity_values: [],
            observable_values: [],
            rule_ids: [r.rule_id],
          },
        });
        setMutedRuleIds((prev) => new Set(prev).add(r.rule_id));
        // The backend already suppressed matching findings — let the parent
        // refresh its inbox so stale active rows disappear immediately.
        onSuppressed?.();
      } catch {
        setError(`Failed to suppress '${r.rule_title}'.`);
      } finally {
        setSuppressingId(null);
      }
    },
    [onSuppressed],
  );

  const neverRun = baseline?.never_run ?? [];
  if (!baseline || (baseline.items.length === 0 && neverRun.length === 0)) return null;

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
            {baseline.items.length > 0 && (
              <>
                <VolumeX className="w-4 h-4 text-amber-400" aria-hidden="true" />
                <span>Noisy rules ({baseline.items.length})</span>
              </>
            )}
            {neverRun.length > 0 && (
              <>
                <EyeOff className="w-4 h-4 text-rose-400" aria-hidden="true" />
                <span data-testid="never-run-count">{neverRun.length} never run</span>
              </>
            )}
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
            {baseline.items.length > 0 && (
              <p className="text-xs text-muted-foreground">
                These pack rules hit on nearly every run over the last{" "}
                {baseline.runs_analyzed} run{baseline.runs_analyzed === 1 ? "" : "s"} — likely
                baseline activity. Nothing is suppressed automatically
                {canSuppress
                  ? "; Suppress rule mutes exactly that detection rule."
                  : "; suppression requires senior_analyst or higher."}
              </p>
            )}
            {error && (
              <p className="text-xs text-rose-300" data-testid="noisy-rules-error">
                {error}
              </p>
            )}
            {baseline.items.map((r) => {
              const isMuted = mutedRuleIds.has(r.rule_id);
              const isSuppressing = suppressingId === r.rule_id;
              return (
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
                    {isMuted ? (
                      <span
                        className="rounded border border-emerald-500/30 bg-emerald-600/20 px-1.5 py-0.5 text-emerald-300"
                        data-testid={`noisy-rule-muted-${r.rule_id}`}
                      >
                        suppressed
                      </span>
                    ) : (
                      canSuppress && (
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={isSuppressing}
                          onClick={() => void handleSuppress(r)}
                          data-testid={`noisy-rule-suppress-${r.rule_id}`}
                          title="Create a suppression targeting exactly this rule"
                        >
                          {isSuppressing ? (
                            <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <VolumeX className="w-3.5 h-3.5" />
                          )}
                          <span className="ml-1">Suppress rule</span>
                        </Button>
                      )
                    )}
                  </div>
                </div>
              );
            })}

            {neverRun.length > 0 && (
              <div
                className="mt-3 space-y-2 border-t border-border/60 pt-3"
                data-testid="never-run-section"
              >
                <p className="text-xs text-muted-foreground">
                  These rules are enabled but no sweep in the last {neverRun[0]!.window_days} days
                  ever executed them — the rules-per-sweep cap or the per-run deadline stopped the
                  runner first, every time. They have no hit statistics because they have never
                  run, so a quiet pack here is a blind spot, not a clean result. Raise the cap,
                  lengthen the deadline, or split the pack.
                </p>
                {neverRun.map((r) => (
                  <div
                    key={`${r.pack_id}:${r.rule_id}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/60 bg-muted/20 px-3 py-2"
                    data-testid={`never-run-rule-${r.rule_id}`}
                  >
                    <div className="min-w-0">
                      <p className="truncate font-mono text-sm text-foreground">{r.rule_id}</p>
                      <p className="text-xs text-muted-foreground">{r.pack_name}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2 text-xs">
                      <span
                        className="rounded border border-rose-500/30 bg-rose-600/20 px-1.5 py-0.5 text-rose-300"
                        data-testid={`never-run-skips-${r.rule_id}`}
                      >
                        skipped by {r.runs_skipped} sweep{r.runs_skipped === 1 ? "" : "s"}
                      </span>
                      <span className="text-muted-foreground">
                        {r.days_dark} day{r.days_dark === 1 ? "" : "s"} dark
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
