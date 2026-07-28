import { useCallback, useEffect, useMemo, useState } from "react";
import { CalendarClock, Loader2, Map as MapIcon } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { getCoverageMap } from "@/api/validation";
import type { CoverageMapEntry } from "@/types/validation";

const VERDICT_STYLE: Record<string, string> = {
  validated: "text-emerald-400",
  wrong_severity: "text-amber-400",
  late: "text-amber-400",
  silent_gap: "text-rose-400",
  errored: "text-rose-400",
};

function ageLabel(entry: CoverageMapEntry): string {
  if (entry.last_validated == null || entry.days_since_validated == null) {
    return "never validated";
  }
  const d = entry.days_since_validated;
  return d === 0 ? "today" : `${d}d ago`;
}

/**
 * Per-technique coverage map (#118 Phase C).
 *
 * `GET /validation/coverage-map` shipped in #471 with no consumer, so the
 * question the whole validation arc exists to answer — *which of our detections
 * haven't been proven to work lately* — had no way to be asked in the product.
 *
 * Two notes on how this fetches:
 *
 * The endpoint has an `only_stale` filter, but this panel fetches **unfiltered**
 * and filters on the server-computed `stale` flag client-side. That isn't
 * duplicating server logic — `stale` is just read, never recomputed — and it
 * buys honest empty states: with a server-side filter, zero rows is ambiguous
 * between "nothing is stale" (good) and "there is no coverage data at all"
 * (very much not good), and those must not read the same. One request also
 * gives both counts for the header. The set is bounded — only techniques the
 * org has a detection for or has already validated — so this is not a large
 * fetch.
 *
 * Stale-only is the default view. An operator opening this wants the actionable
 * subset, not a full matrix they have to scan for problems.
 */
export function CoverageMapPanel({
  onValidateTechnique,
}: {
  onValidateTechnique?: (techniqueId: string) => void;
}) {
  const [entries, setEntries] = useState<CoverageMapEntry[] | null>(null);
  const [staleDays, setStaleDays] = useState(90);
  const [daysInput, setDaysInput] = useState("90");
  const [staleOnly, setStaleOnly] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (days: number) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await getCoverageMap({ staleDays: days });
      setEntries(resp.items);
    } catch {
      setError("Could not load the coverage map.");
      setEntries(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(staleDays);
  }, [load, staleDays]);

  const staleCount = useMemo(
    () => (entries ?? []).filter((e) => e.stale).length,
    [entries],
  );
  const visible = useMemo(
    () => (staleOnly ? (entries ?? []).filter((e) => e.stale) : (entries ?? [])),
    [entries, staleOnly],
  );

  if (error) {
    return (
      <section className="mb-6" data-testid="coverage-map-error" role="alert">
        <p className="text-xs text-severity-medium">{error}</p>
      </section>
    );
  }

  return (
    <section
      className="mb-6 rounded-lg border border-border bg-card/50 p-4"
      data-testid="coverage-map-panel"
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <MapIcon className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Coverage map</h2>
        <span className="text-xs text-muted-foreground" data-testid="coverage-map-counts">
          {entries === null
            ? "loading…"
            : `${staleCount} of ${entries.length} stale (>${staleDays}d or never)`}
        </span>
        {loading && (
          <Loader2
            className="h-3.5 w-3.5 animate-spin text-muted-foreground"
            aria-label="Loading coverage map"
          />
        )}
        <div className="ml-auto flex items-center gap-3">
          <label className="inline-flex cursor-pointer items-center gap-1.5 text-xs">
            <input
              type="checkbox"
              checked={staleOnly}
              onChange={() => setStaleOnly((v) => !v)}
              className="h-4 w-4 accent-primary"
              data-testid="coverage-map-stale-only"
            />
            Stale only
          </label>
          <form
            className="flex items-center gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              const n = Number(daysInput);
              // Mirrors the server bound (ge=1, le=3650); an out-of-range value
              // would 422 and read as a broken panel.
              if (Number.isFinite(n) && n >= 1 && n <= 3650) setStaleDays(Math.floor(n));
            }}
          >
            <CalendarClock className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
            <Input
              value={daysInput}
              onChange={(e) => setDaysInput(e.target.value)}
              aria-label="Stale after (days)"
              data-testid="coverage-map-stale-days"
              className="h-8 w-20"
            />
            <Button type="submit" size="sm" variant="ghost" data-testid="coverage-map-apply">
              Apply
            </Button>
          </form>
        </div>
      </div>

      {entries !== null && entries.length === 0 ? (
        // "No rows" with the filter on would otherwise read as "all good".
        <p className="text-xs text-muted-foreground" data-testid="coverage-map-no-data">
          No coverage data yet — no technique has a detection or a validation run.
        </p>
      ) : visible.length === 0 && entries !== null ? (
        <p className="text-xs text-emerald-400" data-testid="coverage-map-none-stale">
          Every covered technique has been validated within {staleDays} days.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs" data-testid="coverage-map-table">
            <thead>
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Technique</th>
                <th className="py-2 pr-4 font-medium">Last validated</th>
                <th className="py-2 pr-4 font-medium">Verdict</th>
                <th className="py-2 pr-4 font-medium">Detection</th>
                <th className="py-2 pr-4 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {visible.map((e) => (
                <tr key={e.technique_id} data-testid={`coverage-map-row-${e.technique_id}`}>
                  <td className="py-2 pr-4">
                    <span className="font-mono">{e.technique_id}</span>
                    {e.name && <span className="ml-2 text-muted-foreground">{e.name}</span>}
                  </td>
                  <td
                    className={`py-2 pr-4 ${e.stale ? "text-rose-300" : "text-muted-foreground"}`}
                    data-testid={`coverage-map-age-${e.technique_id}`}
                  >
                    {ageLabel(e)}
                  </td>
                  <td className={`py-2 pr-4 ${VERDICT_STYLE[e.last_verdict ?? ""] ?? ""}`}>
                    {e.last_verdict ? e.last_verdict.replace(/_/g, " ") : "—"}
                  </td>
                  <td className="py-2 pr-4">
                    {e.has_detection ? (
                      <span className="text-muted-foreground">yes</span>
                    ) : (
                      // Validated but with no detection authored is a
                      // different problem from a stale detection, so it gets
                      // its own marker rather than an empty cell.
                      <span className="text-amber-400" data-testid={`coverage-map-nodetect-${e.technique_id}`}>
                        none
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-4 text-right">
                    {onValidateTechnique && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onValidateTechnique(e.technique_id)}
                        data-testid={`coverage-map-validate-${e.technique_id}`}
                        title="Load this technique into the emulation trigger"
                      >
                        Validate
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
