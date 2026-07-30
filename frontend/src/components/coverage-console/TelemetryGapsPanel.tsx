/**
 * Telemetry-gaps panel (#501, made a real signal by #113-persistence).
 *
 * Two different failures share this panel, and the whole point is that they are
 * rendered as two different things:
 *
 *  - `ocsf_telemetry_gap` — the **persisted** #113 DataSourceMatcher verdict:
 *    no connector the org has connected emits an OCSF class the rule needs, so
 *    the rule *cannot fire*, and the missing classes are named. This is a stored
 *    fact, badged `persisted`.
 *  - `backends_errored` / `never_validated` — the older, weaker heuristic
 *    inferred from the stored validation blob: the rule may well work, nobody
 *    has proven it. Badged `derived`.
 *
 * Originally the panel could only ever show the second kind (the matcher output
 * had no column to live in), and its copy claimed more than that supported. The
 * provenance badge exists so a derived guess can never again be read as a
 * measured gap.
 *
 * It computes nothing: reason, signal and the missing-class list are all read
 * off the server payload.
 */

import { Link } from "react-router";
import { DatabaseZap } from "lucide-react";
import type { TelemetryGap } from "@/types/coverage";

const REASON_LABEL: Record<TelemetryGap["reason"], string> = {
  ocsf_telemetry_gap: "no connected telemetry",
  backends_errored: "no backend could run it",
  never_validated: "never validated",
};

const REASON_STYLE: Record<TelemetryGap["reason"], string> = {
  ocsf_telemetry_gap: "text-rose-400",
  backends_errored: "text-rose-400",
  never_validated: "text-amber-400",
};

const SIGNAL_LABEL: Record<TelemetryGap["signal"], string> = {
  persisted: "measured",
  derived: "inferred",
};

const SIGNAL_TITLE: Record<TelemetryGap["signal"], string> = {
  persisted:
    "Measured: the stored DataSourceMatcher result for this rule — no connected connector emits the telemetry it needs.",
  derived:
    "Inferred from the rule's stored validation outcome — it may still work; it has not been proven.",
};

const SIGNAL_STYLE: Record<TelemetryGap["signal"], string> = {
  persisted: "border-rose-400/40 bg-rose-500/10 text-rose-200",
  derived: "border-border bg-background/60 text-muted-foreground",
};

export function TelemetryGapsPanel({
  gaps,
  measuredCount,
}: {
  gaps: TelemetryGap[];
  /** `summary.ocsf_telemetry_gaps` — the server's count, not a re-tally here. */
  measuredCount: number;
}) {
  const measured = measuredCount;

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
        {measured > 0 && (
          <span
            className="rounded border border-rose-400/40 bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-200"
            data-testid="telemetry-gaps-measured-count"
            title="Rules that cannot fire: a required OCSF class is emitted by nothing the org has connected."
          >
            {measured} cannot fire
          </span>
        )}
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
          Every proposed detection reconciles against connected telemetry and has been exercised
          against it.
        </p>
      ) : (
        <ul className="divide-y divide-border/50 text-xs" data-testid="telemetry-gaps-list">
          {gaps.map((g) => (
            <li
              key={`${g.proposal_row_id}:${g.technique_id}`}
              className="py-2"
              data-testid={`telemetry-gap-${g.technique_id}`}
              data-signal={g.signal}
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
                <span
                  className={`rounded border px-1 py-0.5 text-[10px] ${SIGNAL_STYLE[g.signal]}`}
                  data-testid={`telemetry-gap-signal-${g.technique_id}`}
                  title={SIGNAL_TITLE[g.signal]}
                >
                  {SIGNAL_LABEL[g.signal]}
                </span>
              </div>
              <p className="mt-0.5 text-muted-foreground">{g.title}</p>
              {g.missing_ocsf_classes.length > 0 && (
                <p
                  className="mt-0.5 text-[11px] text-rose-300"
                  data-testid={`telemetry-gap-missing-ocsf-${g.technique_id}`}
                >
                  no connector emits: {g.missing_ocsf_classes.join(", ")}
                </p>
              )}
              {g.data_sources_required.length > 0 && (
                <p
                  className="mt-0.5 text-[11px] text-muted-foreground"
                  data-testid={`telemetry-gap-sources-${g.technique_id}`}
                >
                  partly covered by: {g.data_sources_required.join(", ")}
                </p>
              )}
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
