import { useState, useCallback, useEffect } from "react";
import { History, ChevronDown, ChevronRight, Crosshair, CircleOff } from "lucide-react";
import { Badge } from "@/components/ds/badge";
import { Button } from "@/components/ds/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ds/card";
import {
  listTechniqueExercises,
  listExerciseGaps,
  type TechniqueExercise,
  type ExerciseGap,
} from "@/api/mitre";

const STALE_DAYS = 90;
const GAPS_PAGE_SIZE = 25;

type ViewMode = "all" | "stale" | "never";

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

const EMPTY_TEXT: Record<ViewMode, string> = {
  all: "No hunts have exercised techniques yet. Execute a hunt plan to start tracking.",
  stale: `No stale coverage — every exercised technique ran within ${STALE_DAYS} days.`,
  never: "No gaps — every technique in the corpus has been exercised at least once.",
};

/** Hunt exercise coverage (#99 Phase C): which techniques the hunt
 *  machinery actually looked at recently — and which it never has. */
export function ExercisePanel() {
  const [exercises, setExercises] = useState<TechniqueExercise[]>([]);
  const [gaps, setGaps] = useState<ExerciseGap[]>([]);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<ViewMode>("all");

  const fetchView = useCallback(async (view: ViewMode) => {
    try {
      if (view === "never") {
        const resp = await listExerciseGaps({ page_size: GAPS_PAGE_SIZE });
        setGaps(resp.items);
        setTotal(resp.total);
      } else {
        const resp = await listTechniqueExercises(
          view === "stale" ? { older_than_days: STALE_DAYS } : undefined,
        );
        setExercises(resp.items);
        setTotal(resp.total);
      }
    } catch {
      // Advisory panel — never block the matrix on it.
    }
  }, []);

  useEffect(() => {
    void fetchView(mode);
  }, [fetchView, mode]);

  const isEmpty = mode === "never" ? gaps.length === 0 : exercises.length === 0;

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
            <div className="flex items-center gap-1">
              {(
                [
                  ["all", "All"],
                  ["stale", `Stale >${STALE_DAYS}d`],
                  ["never", "Never exercised"],
                ] as const
              ).map(([value, label]) => (
                <Button
                  key={value}
                  variant={mode === value ? "secondary" : "ghost"}
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => setMode(value)}
                  data-testid={`exercise-mode-${value}`}
                >
                  {label}
                </Button>
              ))}
            </div>
          )}
        </div>
      </CardHeader>
      {open && (
        <CardContent className="space-y-2 pt-0">
          {isEmpty ? (
            <p className="text-sm text-muted-foreground" data-testid="exercise-empty">
              {EMPTY_TEXT[mode]}
            </p>
          ) : mode === "never" ? (
            gaps.map((g) => (
              <div
                key={g.technique_id}
                className="flex items-center justify-between gap-3 rounded-md border border-border p-2.5 text-sm"
                data-testid={`gap-row-${g.technique_id}`}
              >
                <div className="flex min-w-0 items-center gap-2">
                  <CircleOff className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
                  <span className="font-mono font-medium text-foreground">
                    {g.technique_id}
                  </span>
                  <span className="truncate text-xs text-muted-foreground">{g.name}</span>
                </div>
                <Badge variant="outline" className="shrink-0">
                  {g.tactic}
                </Badge>
              </div>
            ))
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
