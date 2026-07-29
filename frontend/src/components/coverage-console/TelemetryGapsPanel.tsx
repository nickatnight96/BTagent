/**
 * Telemetry-gaps panel (#501).
 *
 * Techniques whose detection cannot currently be *proven* against the org's
 * telemetry: either every backend errored when the rule was validated
 * (`backends_errored`) or the rule has never been validated at all
 * (`never_validated`). Both are coverage that only looks present on a matrix.
 *
 * The two reasons are rendered distinctly on purpose — "the SIEM refused us"
 * and "nobody has checked" need different fixes, and collapsing them would hide
 * which one you have.
 */

import { Link } from "react-router";
import { DatabaseZap } from "lucide-react";
import type { TelemetryGap } from "@/types/coverage";

const REASON_LABEL: Record<TelemetryGap["reason"], string> = {
  backends_errored: "no backend could run it",
  never_validated: "never validated",
};

const REASON_STYLE: Record<TelemetryGap["reason"], string> = {
  backends_errored: "text-rose-400",
  never_validated: "text-amber-400",
};

export function TelemetryGapsPanel({ gaps }: { gaps: TelemetryGap[] }) {
  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="telemetry-gaps-panel"
    >
      <div className="mb-3 flex items-center gap-2">
        <DatabaseZap className="h-4 w-4 text-sky-400" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Telemetry gaps</h2>
        <span className="text-xs text-muted-foreground" data-testid="telemetry-gaps-count">
          {gaps.length}
        </span>
        <Link
          to="/detection-proposals"
          className="ml-auto text-xs text-primary hover:underline"
          data-testid="telemetry-gaps-link"
        >
          Detection Proposals →
        </Link>
      </div>

      {gaps.length === 0 ? (
        <p className="text-xs text-emerald-400" data-testid="telemetry-gaps-none">
          Every proposed detection has been exercised against real telemetry.
        </p>
      ) : (
        <ul className="divide-y divide-border/50 text-xs" data-testid="telemetry-gaps-list">
          {gaps.map((g) => (
            <li
              key={`${g.proposal_row_id}:${g.technique_id}`}
              className="py-2"
              data-testid={`telemetry-gap-${g.technique_id}`}
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono">{g.technique_id}</span>
                {g.name && <span className="text-muted-foreground">{g.name}</span>}
                <span
                  className={`ml-auto ${REASON_STYLE[g.reason]}`}
                  data-testid={`telemetry-gap-reason-${g.technique_id}`}
                >
                  {REASON_LABEL[g.reason]}
                </span>
              </div>
              <p className="mt-0.5 text-muted-foreground">{g.title}</p>
              {g.unavailable_backends.length > 0 && (
                <p className="mt-0.5 text-[11px] text-rose-300">
                  unavailable: {g.unavailable_backends.join(", ")}
                </p>
              )}
              {g.attack_data_sources.length > 0 && (
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  needs: {g.attack_data_sources.join(", ")}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
