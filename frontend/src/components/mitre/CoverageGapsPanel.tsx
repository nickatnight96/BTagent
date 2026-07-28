import { useCallback, useEffect, useState } from "react";
import { Radar, ShieldOff } from "lucide-react";
import { Badge } from "@/components/ds/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ds/card";
import { getDetectionGaps, suggestTTPsForEnvironment } from "@/api/mitre";
import type { DetectionGap, MitreTechnique } from "@/types/mitre";

function prettyTactic(shortname: string): string {
  return shortname.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * Detection gaps + environment-relevant TTPs (#100 / MITRE).
 *
 * `GET /mitre/gaps` and `GET /mitre/search-ttps` both shipped without a
 * consumer, so the two questions they answer — *what have we no detection
 * for* and *what should we care about given what we run* — could only be
 * asked with curl. The reachability ratchet (#473) named both.
 *
 * Deliberately paired with, not merged into, the exercise panel above it.
 * They answer different questions and conflating them would be misleading:
 *
 * * the exercise panel asks "has a hunt *looked* at this technique lately?"
 * * this one asks "is there a detection for it *at all*?"
 *
 * A technique can be freshly exercised and still have no detection, or have
 * a detection nobody has tested in a year. Both are gaps; they are not the
 * same gap, and a single merged number would hide that.
 */
export function CoverageGapsPanel() {
  const [gaps, setGaps] = useState<DetectionGap[] | null>(null);
  const [ttps, setTtps] = useState<MitreTechnique[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    // Fetched independently: the org-profile suggestion is the softer of the
    // two, and losing it must not take the gap list — the harder finding —
    // down with it.
    const [gapResult, ttpResult] = await Promise.allSettled([
      getDetectionGaps(),
      suggestTTPsForEnvironment(),
    ]);
    if (gapResult.status === "fulfilled") setGaps(gapResult.value);
    if (ttpResult.status === "fulfilled") setTtps(ttpResult.value);
    if (gapResult.status === "rejected" && ttpResult.status === "rejected") {
      setError("Could not load coverage gaps.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <p className="text-xs text-severity-medium" role="alert" data-testid="coverage-gaps-error">
        {error}
      </p>
    );
  }
  if (gaps === null && ttps === null) return null;

  const totalUncovered = (gaps ?? []).reduce(
    (n, g) => n + g.techniques_without_detection.length,
    0,
  );

  return (
    <Card data-testid="coverage-gaps-panel">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldOff className="h-4 w-4 text-primary" aria-hidden="true" />
          Detection gaps
          {gaps !== null && (
            <span className="text-xs font-normal text-muted-foreground">
              {totalUncovered} technique{totalUncovered === 1 ? "" : "s"} with no detection
              across {gaps.length} tactic{gaps.length === 1 ? "" : "s"}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {gaps !== null &&
          (gaps.length === 0 ? (
            <p className="text-xs text-emerald-400" data-testid="coverage-gaps-none">
              Every tactic has detection data.
            </p>
          ) : (
            <ul className="space-y-2" data-testid="coverage-gaps-list">
              {gaps.map((g) => (
                <li
                  key={g.tactic}
                  className="rounded-md border border-border bg-card/50 p-3 text-xs"
                  data-testid={`coverage-gap-${g.tactic}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{prettyTactic(g.tactic)}</span>
                    <Badge variant="destructive">
                      {g.techniques_without_detection.length} uncovered
                    </Badge>
                  </div>
                  {g.techniques_without_detection.length > 0 && (
                    <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                      {g.techniques_without_detection.join(", ")}
                    </p>
                  )}
                  {g.data_sources_missing.length > 0 && (
                    // The missing data sources are the actionable half: they
                    // say what to onboard, not just what is absent.
                    <p
                      className="mt-1 text-amber-400"
                      data-testid={`coverage-gap-sources-${g.tactic}`}
                    >
                      would need: {g.data_sources_missing.join(", ")}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          ))}

        {ttps !== null && (
          <div data-testid="env-ttps">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
              <Radar className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
              Relevant to your stack
              <span className="font-normal text-muted-foreground">
                derived from the organisation profile
              </span>
            </p>
            {ttps.length === 0 ? (
              // "No suggestions" usually means an unfilled profile, not a
              // clean bill of health — say which.
              <p className="text-xs text-muted-foreground" data-testid="env-ttps-empty">
                No suggestions — the organisation profile has no tech stack recorded.
              </p>
            ) : (
              <ul className="flex flex-wrap gap-1.5" data-testid="env-ttps-list">
                {ttps.map((t) => (
                  <li
                    key={t.id}
                    className="rounded border border-border px-1.5 py-0.5 text-[11px]"
                    data-testid={`env-ttp-${t.id}`}
                    title={t.name}
                  >
                    <span className="font-mono">{t.id}</span>{" "}
                    <span className="text-muted-foreground">{t.name}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
