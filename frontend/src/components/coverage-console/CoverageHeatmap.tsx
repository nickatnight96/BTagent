/**
 * MITRE-matrix-style coverage heatmap (#501).
 *
 * One column per ATT&CK tactic, one cell per technique, coloured by the
 * server-computed validation-freshness band (`status`). The band is *read*,
 * never recomputed here — the whole point of the console is that one
 * aggregation decides what "stale" means so every surface agrees.
 *
 * Clicking a cell hands the technique to the caller (the page loads it into the
 * validation surface); the heatmap itself never triggers anything.
 */

import { useMemo, useState } from "react";
import { Grid3X3 } from "lucide-react";
import {
  STATUS_LABEL,
  STATUS_SWATCH,
  cellTitle,
  tacticLabel,
} from "./coverage-format";
import type { CoverageStatus, TacticColumn } from "@/types/coverage";

const BANDS: CoverageStatus[] = ["fresh", "stale", "never", "silent_gap"];

export function CoverageHeatmap({
  tactics,
  onSelectTechnique,
}: {
  tactics: TacticColumn[];
  onSelectTechnique?: (techniqueId: string) => void;
}) {
  // Band filter. Null = show everything; the operator most often wants the
  // red/amber subset, but defaulting to a filter would hide the good news the
  // heatmap exists to show.
  const [band, setBand] = useState<CoverageStatus | null>(null);

  const columns = useMemo(() => {
    if (band === null) return tactics;
    return tactics
      .map((col) => ({ ...col, techniques: col.techniques.filter((t) => t.status === band) }))
      .filter((col) => col.techniques.length > 0);
  }, [tactics, band]);

  if (tactics.length === 0) {
    return (
      <section
        className="rounded-lg border border-border bg-card/50 p-4"
        data-testid="coverage-heatmap-empty"
      >
        <div className="mb-2 flex items-center gap-2">
          <Grid3X3 className="h-4 w-4 text-primary" aria-hidden="true" />
          <h2 className="text-sm font-semibold">Technique coverage</h2>
        </div>
        <p className="text-xs text-muted-foreground">
          No coverage data yet — no technique has a detection proposal or a validation run.
          Import intel or run a validation to populate the matrix.
        </p>
      </section>
    );
  }

  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="coverage-heatmap"
    >
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Grid3X3 className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Technique coverage</h2>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {BANDS.map((b) => (
            <button
              key={b}
              type="button"
              onClick={() => setBand((cur) => (cur === b ? null : b))}
              className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[11px] transition ${
                band === b ? "border-primary text-foreground" : "border-border text-muted-foreground"
              }`}
              data-testid={`coverage-heatmap-band-${b}`}
              title={STATUS_LABEL[b]}
            >
              <span
                className={`inline-block h-2.5 w-2.5 rounded-sm border ${STATUS_SWATCH[b]}`}
                aria-hidden="true"
              />
              {b.replace(/_/g, " ")}
            </button>
          ))}
        </div>
      </div>

      {columns.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="coverage-heatmap-band-empty">
          No techniques in this band.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <div className="flex min-w-max gap-3">
            {columns.map((col) => (
              <div
                key={col.tactic}
                className="w-40 shrink-0"
                data-testid={`coverage-tactic-${col.tactic}`}
              >
                <div className="mb-2 border-b border-border pb-1">
                  <p className="truncate text-xs font-medium" title={tacticLabel(col.tactic)}>
                    {tacticLabel(col.tactic)}
                  </p>
                  <p className="text-[10px] text-muted-foreground">
                    {col.techniques.length} technique{col.techniques.length === 1 ? "" : "s"}
                  </p>
                </div>
                <div className="flex flex-col gap-1">
                  {col.techniques.map((cell) => (
                    <button
                      key={cell.technique_id}
                      type="button"
                      onClick={() => onSelectTechnique?.(cell.technique_id)}
                      title={cellTitle(cell)}
                      data-testid={`coverage-cell-${cell.technique_id}`}
                      data-status={cell.status}
                      className={`rounded border px-2 py-1 text-left text-[11px] leading-tight transition hover:brightness-125 ${
                        STATUS_SWATCH[cell.status]
                      }`}
                    >
                      <span className="block font-mono">{cell.technique_id}</span>
                      {cell.name && <span className="block truncate opacity-90">{cell.name}</span>}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
