/**
 * Shift-handover card (EPIC-5 UC-5.1).
 *
 * Sits at the top of the PunchList: on mount it pulls the org's handover
 * summary (`GET /handover`, default 8h window) and renders the deterministic
 * headline plus the numbers an analyst scans at shift start — hunt findings
 * landed by severity, how many are still untriaged, and the open-case
 * backlog. Best-effort: a fetch failure renders nothing rather than blocking
 * the punch list.
 */

import { useEffect, useState } from "react";
import { ArrowRightLeft } from "lucide-react";
import { Card, CardContent } from "@/components/ds/card";
import { getHandoverSummary } from "@/api/handover";
import type { HandoverSummary } from "@/types/handover";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function severityChipClass(severity: string): string {
  if (severity === "critical") return "border-rose-500/40 text-rose-300";
  if (severity === "high") return "border-amber-500/40 text-amber-300";
  return "border-border text-muted-foreground";
}

function orderedEntries(counts: Record<string, number>): Array<[string, number]> {
  return SEVERITY_ORDER.filter((s) => counts[s]).map((s) => [s, counts[s] as number]);
}

export function HandoverCard() {
  const [summary, setSummary] = useState<HandoverSummary | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const resp = await getHandoverSummary();
        if (!cancelled) setSummary(resp);
      } catch {
        // Advisory surface only — never block the punch list on it.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!summary) return null;

  const findings = orderedEntries(summary.findings_by_severity);
  const backlog = orderedEntries(summary.open_by_severity);

  return (
    <Card className="mb-6" data-testid="handover-card">
      <CardContent className="py-4 space-y-3">
        <div className="flex items-center gap-2">
          <ArrowRightLeft className="w-4 h-4 text-sky-400" aria-hidden="true" />
          <span className="text-sm font-semibold text-foreground">Shift handover</span>
          <span className="text-xs text-muted-foreground">
            last {summary.window_hours}h
          </span>
        </div>

        <p className="text-sm text-muted-foreground" data-testid="handover-headline">
          {summary.headline}
        </p>

        <div className="flex flex-wrap items-center gap-4 text-xs">
          {findings.length > 0 && (
            <div className="flex items-center gap-1.5" data-testid="handover-findings">
              <span className="text-muted-foreground">Findings:</span>
              {findings.map(([severity, count]) => (
                <span
                  key={severity}
                  className={`rounded border px-1.5 py-0.5 font-medium ${severityChipClass(severity)}`}
                  data-testid={`handover-finding-${severity}`}
                >
                  {count} {severity}
                </span>
              ))}
              {summary.findings_untriaged > 0 && (
                <span
                  className="rounded border border-sky-500/40 px-1.5 py-0.5 font-medium text-sky-300"
                  data-testid="handover-untriaged"
                >
                  {summary.findings_untriaged} untriaged
                </span>
              )}
            </div>
          )}
          {backlog.length > 0 && (
            <div className="flex items-center gap-1.5" data-testid="handover-backlog">
              <span className="text-muted-foreground">Open backlog:</span>
              {backlog.map(([severity, count]) => (
                <span
                  key={severity}
                  className={`rounded border px-1.5 py-0.5 font-medium ${severityChipClass(severity)}`}
                  data-testid={`handover-open-${severity}`}
                >
                  {count} {severity}
                </span>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
