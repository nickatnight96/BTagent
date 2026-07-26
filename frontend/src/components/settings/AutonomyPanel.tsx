import { useEffect, useState } from "react";
import { Bot, Loader2, Lock, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import { getAutonomyConfig, putAutonomyOverrides } from "@/api/configSchema";
import type { AutonomyConfig } from "@/types/configSchema";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { NativeSelect } from "@/components/ds/native-select";

const LEVEL_BADGE: Record<string, string> = {
  L0: "border-rose-500/40 text-rose-300",
  L1: "border-amber-500/40 text-amber-300",
  L2: "border-sky-500/40 text-sky-300",
  L3: "border-emerald-500/40 text-emerald-300",
  L4: "border-emerald-500/40 text-emerald-300",
};

const LEVELS = ["L0", "L1", "L2", "L3", "L4"] as const;

/**
 * Autonomy & HITL gates (#418 slice 8). Admins set per-category org
 * overrides via level selects (every write sends the FULL overrides dict —
 * the PUT is wholesale-replace; choosing "default" removes the override).
 * Containment categories render locked: they are HITL-gated in code and the
 * backend rejects any attempt to configure them. Non-admins see the
 * effective levels read-only. Fetch failure hides the panel.
 */
export function AutonomyPanel() {
  const role = useAuthStore((s) => s.user?.role);
  const isAdmin = role === UserRole.ADMIN;

  const [config, setConfig] = useState<AutonomyConfig | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getAutonomyConfig()
      .then((resp) => {
        if (!cancelled) setConfig(resp);
      })
      .catch(() => {
        if (!cancelled) setConfig(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (config === null) return null;

  const overrides: Record<string, string> = Object.fromEntries(
    config.categories.filter((c) => c.overridden).map((c) => [c.key, c.level]),
  );

  const persist = async (next: Record<string, string>) => {
    setBusy(true);
    try {
      const resp = await putAutonomyOverrides(next);
      setConfig(resp);
    } catch {
      toast.error("Could not save autonomy overrides");
    } finally {
      setBusy(false);
    }
  };

  const handleLevelChange = (key: string, value: string) => {
    const next = { ...overrides };
    if (value === "") {
      delete next[key];
    } else {
      next[key] = value;
    }
    void persist(next);
  };

  return (
    <section data-testid="config-center-autonomy">
      <div className="flex items-center gap-2 mb-3">
        <Bot className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Autonomy &amp; HITL gates</h2>
        <span className="text-xs text-muted-foreground flex-1">
          {isAdmin
            ? "per-org overrides; containment is locked in code"
            : "read-only (admin-managed)"}
        </span>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Saving"
          />
        )}
        {isAdmin && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void persist({})}
            disabled={busy || Object.keys(overrides).length === 0}
            data-testid="autonomy-reset-button"
          >
            <RotateCcw className="w-3.5 h-3.5 mr-1.5" aria-hidden="true" />
            Reset to defaults
          </Button>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {config.categories.map((cat) => (
          <span
            key={cat.key}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card/50 px-2.5 py-1.5 text-xs"
            data-testid={`autonomy-category-${cat.key}`}
            title={config.levels[cat.level] ?? cat.level}
          >
            {cat.key.replace(/_/g, " ")}
            {isAdmin && !cat.hitl_forced ? (
              <NativeSelect
                value={cat.overridden ? cat.level : ""}
                disabled={busy}
                onChange={(e) => handleLevelChange(cat.key, e.target.value)}
                aria-label={`Autonomy level for ${cat.key}`}
                data-testid={`autonomy-select-${cat.key}`}
                className="h-7 w-28 text-xs"
              >
                <option value="">default</option>
                {LEVELS.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </NativeSelect>
            ) : (
              <span
                className={`rounded border px-1 py-0.5 text-[10px] font-semibold ${
                  LEVEL_BADGE[cat.level] ?? "border-border text-muted-foreground"
                }`}
              >
                {cat.level}
              </span>
            )}
            {cat.overridden && (
              <span
                className="rounded border border-amber-500/40 px-1 py-0.5 text-[10px] text-amber-300"
                data-testid={`autonomy-overridden-${cat.key}`}
              >
                override
              </span>
            )}
            {cat.hitl_forced && (
              <Lock
                className="w-3 h-3 text-rose-300"
                aria-label="Always HITL-gated in code"
                data-testid={`autonomy-hitl-lock-${cat.key}`}
              />
            )}
          </span>
        ))}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        Containment actions stay human-gated in code regardless of the configured
        level.
      </p>
    </section>
  );
}
