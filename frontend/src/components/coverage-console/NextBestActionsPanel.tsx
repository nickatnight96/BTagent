/**
 * Next-best-actions panel (#501).
 *
 * The console's answer to "…so what do I do now?". The server already ranks the
 * list worst-first (proven silent gaps before never-validated before stale) and
 * attaches the route that acts on each, so this renders it in order and links
 * out — it never re-ranks, because two surfaces disagreeing about what is most
 * urgent is worse than either ordering.
 */

import { Link } from "react-router";
import { ArrowRight, ListChecks } from "lucide-react";
import type { NextBestAction } from "@/types/coverage";

const PRIORITY_STYLE = [
  "border-rose-500/50 bg-rose-500/10",
  "border-amber-500/50 bg-amber-500/10",
  "border-sky-500/40 bg-sky-500/10",
];

function priorityStyle(priority: number): string {
  const idx = Math.min(Math.max(priority, 1), PRIORITY_STYLE.length) - 1;
  return PRIORITY_STYLE[idx] ?? PRIORITY_STYLE[PRIORITY_STYLE.length - 1] ?? "";
}

export function NextBestActionsPanel({ actions }: { actions: NextBestAction[] }) {
  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="next-best-actions-panel"
    >
      <div className="mb-3 flex items-center gap-2">
        <ListChecks className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Next best actions</h2>
        <span className="text-xs text-muted-foreground" data-testid="next-best-actions-count">
          {actions.length}
        </span>
      </div>

      {actions.length === 0 ? (
        <p className="text-xs text-emerald-400" data-testid="next-best-actions-none">
          Nothing outstanding — no stale techniques, broken rules, or drafts waiting.
        </p>
      ) : (
        <ul className="space-y-2" data-testid="next-best-actions-list">
          {actions.map((a) => (
            <li key={a.id} data-testid={`next-best-action-${a.id}`}>
              <Link
                to={a.link}
                className={`flex items-start gap-3 rounded-md border px-3 py-2 transition hover:brightness-125 ${priorityStyle(
                  a.priority,
                )}`}
                data-testid={`next-best-action-link-${a.id}`}
              >
                <span className="mt-0.5 shrink-0 rounded bg-background/60 px-1.5 py-0.5 font-mono text-[11px]">
                  {a.count}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-xs font-medium">{a.title}</span>
                  <span className="block text-[11px] text-muted-foreground">{a.detail}</span>
                  {a.technique_ids.length > 0 && (
                    <span className="mt-0.5 block truncate font-mono text-[11px] text-muted-foreground">
                      {a.technique_ids.join(" · ")}
                    </span>
                  )}
                </span>
                <ArrowRight className="mt-0.5 h-3.5 w-3.5 shrink-0 opacity-70" aria-hidden="true" />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
