import { useCallback, useEffect, useState } from "react";
import { Check, Lightbulb, Loader2, X } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import {
  decidePackSuggestion,
  listPackSuggestions,
  type HuntPackSuggestion,
} from "@/api/hunts";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

/** Rule count from the draft manifest, when it carries one. */
function ruleCount(manifest: Record<string, unknown>): number | null {
  const rules = manifest?.rules;
  return Array.isArray(rules) ? rules.length : null;
}

/**
 * Suggested recurring hunt packs (#120/#112).
 *
 * A pattern-hunt proposal that keeps hitting is written out as a *suggested*
 * pack. I shipped that writer, and the read/decide API, without ever giving
 * either a consumer — so suggestions accumulated where nobody could see them
 * and decisions could only be made with curl. The reachability ratchet (#473)
 * named it; this closes it.
 *
 * Placed on the Hunt Packs screen because that is where an accepted suggestion
 * ends up: this panel is the inbox for the list below it.
 *
 * Deciding needs `hunt:promote` (senior_analyst+), enforced server-side.
 * Analysts still *see* the queue — knowing what is pending review is useful at
 * any level — but the buttons are theirs only if they can act.
 */
export function PackSuggestionsPanel() {
  const role = useAuthStore((s) => s.user?.role);
  const canDecide =
    role === UserRole.SENIOR_ANALYST ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.ADMIN;

  const [items, setItems] = useState<HuntPackSuggestion[] | null>(null);
  const [deciding, setDeciding] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const resp = await listPackSuggestions({ state: "suggested" });
      setItems(resp.items);
    } catch {
      // Hide rather than break the page: this is an advisory inbox alongside
      // the installed-pack list, not something the screen depends on.
      setItems(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const decide = async (s: HuntPackSuggestion, state: "accepted" | "dismissed") => {
    setDeciding(s.id);
    setError(null);
    try {
      await decidePackSuggestion(s.id, state);
      // Drop it locally rather than refetching: the row has left the
      // `suggested` queue either way, and a refetch would flash the whole list.
      setItems((prev) => (prev ?? []).filter((x) => x.id !== s.id));
    } catch {
      setError(
        state === "accepted"
          ? `Could not accept "${s.title}" — it was not armed.`
          : `Could not dismiss "${s.title}".`,
      );
    } finally {
      setDeciding(null);
    }
  };

  if (items === null) return null;

  return (
    <section className="space-y-2" data-testid="pack-suggestions-panel">
      <div className="flex items-center gap-2">
        <Lightbulb className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Suggested packs</h2>
        <span className="text-xs text-muted-foreground">
          recurring patterns worth arming as a scheduled pack
        </span>
      </div>

      {error && (
        <p className="text-xs text-destructive" role="alert" data-testid="pack-suggestions-error">
          {error}
        </p>
      )}

      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="pack-suggestions-empty">
          No packs are awaiting a decision.
        </p>
      ) : (
        <ul className="space-y-2" data-testid="pack-suggestions-list">
          {items.map((s) => {
            const rules = ruleCount(s.manifest);
            const busy = deciding === s.id;
            return (
              <li
                key={s.id}
                className="rounded-lg border border-border bg-card/50 p-3 text-sm"
                data-testid={`pack-suggestion-${s.id}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{s.title}</span>
                  <Badge variant="secondary" data-testid={`pack-suggestion-hits-${s.id}`}>
                    {s.hit_count} hit{s.hit_count === 1 ? "" : "s"}
                  </Badge>
                  {s.technique_ids.map((t) => (
                    <span
                      key={t}
                      className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                    >
                      {t}
                    </span>
                  ))}
                  {canDecide && (
                    <span className="ml-auto flex items-center gap-2">
                      {busy && (
                        <Loader2
                          className="w-3.5 h-3.5 animate-spin text-muted-foreground"
                          aria-label="Deciding"
                        />
                      )}
                      <Button
                        size="sm"
                        disabled={busy}
                        onClick={() => void decide(s, "accepted")}
                        data-testid={`pack-suggestion-accept-${s.id}`}
                      >
                        <Check className="w-3.5 h-3.5 mr-1" aria-hidden="true" />
                        Accept
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() => void decide(s, "dismissed")}
                        data-testid={`pack-suggestion-dismiss-${s.id}`}
                      >
                        <X className="w-3.5 h-3.5 mr-1" aria-hidden="true" />
                        Dismiss
                      </Button>
                    </span>
                  )}
                </div>

                <p className="mt-1 text-xs text-muted-foreground">{s.rationale}</p>

                <div className="mt-2 flex items-center gap-3 text-xs">
                  <button
                    onClick={() => setExpanded(expanded === s.id ? null : s.id)}
                    className="text-primary hover:underline"
                    data-testid={`pack-suggestion-toggle-${s.id}`}
                  >
                    {expanded === s.id ? "Hide" : "Review"} draft manifest
                    {rules !== null ? ` (${rules} rule${rules === 1 ? "" : "s"})` : ""}
                  </button>
                  {!canDecide && (
                    <span
                      className="text-muted-foreground"
                      data-testid={`pack-suggestion-readonly-${s.id}`}
                    >
                      arming a pack needs hunt:promote
                    </span>
                  )}
                </div>

                {expanded === s.id && (
                  // Accepting arms a scheduled pack against real telemetry, so
                  // the actual Sigma has to be reviewable before the decision,
                  // not after it.
                  <pre
                    className="mt-2 max-h-64 overflow-auto rounded-md border border-border bg-background/60 p-2 text-[11px]"
                    data-testid={`pack-suggestion-manifest-${s.id}`}
                  >
                    {JSON.stringify(s.manifest, null, 2)}
                  </pre>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
