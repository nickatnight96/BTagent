import { useEffect, useState } from "react";
import { Flag, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { getFeatureFlags, putFeatureFlags } from "@/api/configSchema";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";

// Mirrors the backend's key rule (lowercase snake_case, starts with a letter).
const FLAG_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * Per-org feature-flag toggles (#418 slice 5). Admins flip/add/remove flags;
 * every write sends the FULL updated dict (the PUT is wholesale-replace).
 * Non-admins see the flag set read-only. Fetch failure hides the panel —
 * flags are advisory surface, never a page dependency.
 */
export function FeatureFlagsPanel() {
  const role = useAuthStore((s) => s.user?.role);
  const isAdmin = role === UserRole.ADMIN;

  const [flags, setFlags] = useState<Record<string, boolean> | null>(null);
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getFeatureFlags()
      .then((resp) => {
        if (!cancelled) setFlags(resp.flags);
      })
      .catch(() => {
        if (!cancelled) setFlags(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (flags === null) return null;

  const persist = async (next: Record<string, boolean>) => {
    setBusy(true);
    try {
      const resp = await putFeatureFlags(next);
      setFlags(resp.flags);
    } catch {
      toast.error("Could not save feature flags");
    } finally {
      setBusy(false);
    }
  };

  const handleToggle = (key: string) => {
    void persist({ ...flags, [key]: !flags[key] });
  };

  const handleRemove = (key: string) => {
    const next = { ...flags };
    delete next[key];
    void persist(next);
  };

  const handleAdd = () => {
    const key = newKey.trim();
    if (!FLAG_KEY_RE.test(key)) {
      setKeyError("Keys are lowercase snake_case, starting with a letter (max 64 chars).");
      return;
    }
    if (key in flags) {
      setKeyError("That flag already exists.");
      return;
    }
    setKeyError(null);
    setNewKey("");
    void persist({ ...flags, [key]: false });
  };

  const entries = Object.entries(flags).sort(([a], [b]) => a.localeCompare(b));

  return (
    <section data-testid="feature-flags-panel">
      <div className="flex items-center gap-2 mb-3">
        <Flag className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Feature flags</h2>
        <span className="text-xs text-muted-foreground">
          {isAdmin ? "per-org capability toggles" : "read-only (admin-managed)"}
        </span>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Saving"
          />
        )}
      </div>

      {entries.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="feature-flags-empty">
          No flags configured for this org.
        </p>
      ) : (
        <ul className="space-y-1.5" data-testid="feature-flags-list">
          {entries.map(([key, value]) => (
            <li
              key={key}
              className="flex items-center gap-3 rounded-md border border-border bg-card/50 px-3 py-2 text-xs"
              data-testid={`feature-flag-${key}`}
            >
              <span className="font-mono flex-1">{key}</span>
              {isAdmin ? (
                <>
                  <label className="inline-flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={value}
                      disabled={busy}
                      onChange={() => handleToggle(key)}
                      className="h-4 w-4 accent-primary"
                      aria-label={`Toggle ${key}`}
                      data-testid={`feature-flag-toggle-${key}`}
                    />
                    {value ? "on" : "off"}
                  </label>
                  <button
                    onClick={() => handleRemove(key)}
                    disabled={busy}
                    aria-label={`Remove ${key}`}
                    className="text-muted-foreground hover:text-severity-medium"
                    data-testid={`feature-flag-remove-${key}`}
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                  </button>
                </>
              ) : (
                <span
                  className={value ? "text-emerald-300" : "text-muted-foreground"}
                  data-testid={`feature-flag-state-${key}`}
                >
                  {value ? "on" : "off"}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}

      {isAdmin && (
        <form
          className="mt-3 flex items-start gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            handleAdd();
          }}
        >
          <div className="flex-1 max-w-xs">
            <Input
              value={newKey}
              onChange={(e) => {
                setNewKey(e.target.value);
                setKeyError(null);
              }}
              placeholder="new_flag_key"
              aria-label="New flag key"
              data-testid="feature-flags-add-input"
              className="h-9 font-mono"
            />
            {keyError && (
              <p className="mt-1 text-xs text-severity-medium" role="alert">
                {keyError}
              </p>
            )}
          </div>
          <Button type="submit" size="sm" disabled={busy} data-testid="feature-flags-add-button">
            <Plus className="w-4 h-4 mr-1" aria-hidden="true" />
            Add flag
          </Button>
        </form>
      )}
    </section>
  );
}
