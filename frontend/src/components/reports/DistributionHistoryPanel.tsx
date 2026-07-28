import { useEffect, useState } from "react";
import { Send } from "lucide-react";
import { listReportDistributions } from "@/api/reports";
import type { ReportDistribution } from "@/types/reports";
import { Card, CardContent } from "@/components/ds/card";

/** TLP marking → badge accent. Unknown markings fall back to neutral. */
const TLP_STYLES: Record<string, string> = {
  red: "border-rose-500/40 text-rose-300",
  amber_strict: "border-amber-500/40 text-amber-300",
  amber: "border-amber-500/40 text-amber-300",
  green: "border-emerald-500/40 text-emerald-300",
  white: "border-slate-500/40 text-slate-300",
  clear: "border-slate-500/40 text-slate-300",
};

/**
 * Distribution ledger on the Reports page (EPIC-6 / #473 ratchet).
 *
 * `GET /reports/distributions` is the read side of `record_distribution` —
 * the audit trail of who received which report, under which TLP marking,
 * and who approved the release. The write side has been in use for a while;
 * the ledger itself was reachable only over curl, which for an audit
 * surface is close to not existing: the person who needs it (an IC asking
 * "did the advisory actually go to the ISAC, and at what marking?") is
 * exactly the person who won't reach for curl mid-incident.
 *
 * Self-effacing on fetch failure like every other panel here — the GET is
 * `report:view` (analyst+), so a 403 means nothing on this page works
 * anyway. An empty ledger, by contrast, renders explicitly: "nothing has
 * been distributed" is a meaningful audit statement, not a blank.
 */
export function DistributionHistoryPanel() {
  const [rows, setRows] = useState<ReportDistribution[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    listReportDistributions()
      .then((resp) => {
        if (!cancelled) setRows(resp.distributions);
      })
      .catch(() => {
        if (!cancelled) setRows(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (rows === null) return null;

  return (
    <Card data-testid="reports-distributions-panel">
      <CardContent className="py-4 space-y-4">
        <div className="flex items-center gap-2">
          <Send className="w-4 h-4 text-sky-400" aria-hidden="true" />
          <span className="text-sm font-semibold text-foreground">Distribution history</span>
          <span className="text-xs text-muted-foreground">
            who received which report, at what TLP marking
          </span>
        </div>

        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground" data-testid="reports-distributions-empty">
            No reports have been distributed from this organisation.
          </p>
        ) : (
          <ul className="space-y-2" data-testid="reports-distributions-list">
            {rows.map((d) => (
              <li
                key={d.id}
                className="flex flex-wrap items-center gap-3 rounded-md border border-border/50 bg-background/50 px-3 py-2 text-sm"
                data-testid={`reports-distribution-${d.id}`}
              >
                <span className="font-medium text-foreground">{d.recipient}</span>
                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                  {d.audience}
                </span>
                <span
                  className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
                    TLP_STYLES[d.tlp_applied] ?? "border-border text-muted-foreground"
                  }`}
                  data-testid={`reports-distribution-tlp-${d.id}`}
                >
                  TLP:{d.tlp_applied}
                </span>
                <span className="text-xs text-muted-foreground">
                  report <span className="font-mono">{d.report_id}</span>
                </span>
                <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                  {/* The approver is accountability, not decoration: a RED/
                    * AMBER release with no recorded approver is exactly what
                    * an auditor is scanning this list for. */}
                  {d.approver_id ? (
                    <>approved by {d.approver_id} · </>
                  ) : (
                    <span
                      className="text-amber-300"
                      data-testid={`reports-distribution-unapproved-${d.id}`}
                    >
                      no approver recorded ·{" "}
                    </span>
                  )}
                  {new Date(d.sent_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
