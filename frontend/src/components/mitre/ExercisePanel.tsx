import { useState, useCallback, useEffect } from "react";
import { History, ChevronDown, ChevronRight, Crosshair } from "lucide-react";
import { Badge } from "@/components/ds/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ds/card";
import {
  listTechniqueExercises,
  type TechniqueExercise,
} from "@/api/mitre";

const STALE_DAYS = 90;

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const diffMins = Math.floor((Date.now() - date.getTime()) / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function outcomeVariant(outcome: string): "destructive" | "secondary" | "outline" {
  if (outcome === "hit") return "destructive";
  if (outcome === "clean") return "secondary";
  return "outline";
}

/** Hunt exercise coverage (#99 Phase C): which techniques the hunt
 *  machinery actually looked at recently, and which are going stale. */
export function ExercisePanel() {
  const [exercises, setExercises] = useState<TechniqueExercise[]>([]);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState(false);
  const [staleOnly, setStaleOnly] = useState(false);

  const fetchExercises = useCallback(async (stale: boolean) => {
    try {
      const resp = await listTechniqueExercises(
        stale ? { older_than_days: STALE_DAYS } : undefined,
      );
      setExercises(resp.items);
      setTotal(resp.total);
    } catch {
      // Advisory panel — never block the matrix on it.
    }
  }, []);

  useEffect(() => {
    void fetchExercises(staleOnly);
  }, [fetchExercises, staleOnly]);

  return (
    <Card data-testid="exercise-panel">
      <CardHeader className="py-3">
        <div className="flex items-center justify-between gap-3">
          <button
            type="button"
            className="flex items-center gap-2 text-left"
            onClick={() => setOpen((o) => !o)}
            data-testid="exercise-panel-toggle"
            aria-expanded={open}
          >
            {open ? (
              <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />
            ) : (
              <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
            )}
            <History className="w-4 h-4 text-primary shrink-0" />
            <CardTitle className="text-base">
              Hunt exercise coverage{" "}
              <span className="font-normal text-muted-foreground">({total})</span>
            </CardTitle>
          </button>
          {open && (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={staleOnly}
                onChange={(e) => setStaleOnly(e.target.checked)}
                data-testid="stale-only-toggle"
              />
              Stale &gt;{STALE_DAYS} days only
            </label>
          )}
        </div>
      </CardHeader>
      {open && (
        <CardContent className="space-y-2 pt-0">
          {exercises.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="exercise-empty">
              {staleOnly
                ? `No stale coverage — every exercised technique ran within ${STALE_DAYS} days.`
                : "No hunts have exercised techniques yet. Execute a hunt plan to start tracking."}
            </p>
          ) : (
            exercises.map((e) => (
              <div
                key={e.technique_id}
                className="flex items-center justify-between gap-3 rounded-md border border-border p-2.5 text-sm"
                data-testid={`exercise-row-${e.technique_id}`}
              >
                <div className="flex min-w-0 items-center gap-2">
                  <Crosshair className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
                  <span className="font-mono font-medium text-foreground">
                    {e.technique_id}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    ×{e.exercise_count} · {formatRelativeTime(e.last_exercised_at)}
                  </span>
                </div>
                <Badge variant={outcomeVariant(e.last_outcome)} className="shrink-0">
                  {e.last_outcome}
                </Badge>
              </div>
            ))
          )}
        </CardContent>
      )}
    </Card>
  );
}
