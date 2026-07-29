/**
 * Broken-rules panel (#501) — the #112 "dead 13%" made visible.
 *
 * Rules that errored, fire on everything, or never fire at all. All three look
 * like "coverage" on a matrix and none of them are, which is exactly why they
 * belong next to the heatmap rather than three clicks away in the pack view.
 *
 * Read-only: tuning happens on the Hunt Packs screen, which every row links to.
 */

import { Link } from "react-router";
import { AlertTriangle } from "lucide-react";
import { RULE_STATE_LABEL, RULE_STATE_STYLE } from "./coverage-format";
import type { BrokenRule } from "@/types/coverage";

export function BrokenRulesPanel({ rules }: { rules: BrokenRule[] }) {
  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="broken-rules-panel"
    >
      <div className="mb-3 flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-400" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Broken rules</h2>
        <span className="text-xs text-muted-foreground" data-testid="broken-rules-count">
          {rules.length}
        </span>
        <Link
          to="/hunt-packs"
          className="ml-auto text-xs text-primary hover:underline"
          data-testid="broken-rules-link"
        >
          Hunt Packs →
        </Link>
      </div>

      {rules.length === 0 ? (
        <p className="text-xs text-emerald-400" data-testid="broken-rules-none">
          Every rule with enough run history is firing normally.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs" data-testid="broken-rules-table">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Rule</th>
                <th className="py-2 pr-4 font-medium">State</th>
                <th className="py-2 pr-4 font-medium">Hit rate</th>
                <th className="py-2 pr-4 font-medium">Runs</th>
                <th className="py-2 pr-4 font-medium">Pack</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {rules.map((r) => (
                <tr key={`${r.pack_id}:${r.rule_id}`} data-testid={`broken-rule-${r.rule_id}`}>
                  <td className="py-2 pr-4">{r.rule_title}</td>
                  <td
                    className={`py-2 pr-4 ${RULE_STATE_STYLE[r.state]}`}
                    data-testid={`broken-rule-state-${r.rule_id}`}
                  >
                    {RULE_STATE_LABEL[r.state]}
                    {r.state === "errored" && r.last_errors > 0 && (
                      <span className="ml-1 text-muted-foreground">({r.last_errors})</span>
                    )}
                  </td>
                  <td className="py-2 pr-4">{Math.round(r.hit_rate * 100)}%</td>
                  <td className="py-2 pr-4 text-muted-foreground">
                    {r.runs_hit}/{r.runs_observed}
                  </td>
                  <td className="py-2 pr-4 text-muted-foreground">{r.pack_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
