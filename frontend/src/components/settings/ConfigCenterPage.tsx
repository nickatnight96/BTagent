import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import {
  SlidersHorizontal,
  Loader2,
  AlertTriangle,
  ShieldCheck,
  ExternalLink,
  EyeOff,
} from "lucide-react";
import { getConfigSchema } from "@/api/configSchema";
import type { ConfigSchema, DeployTimeEntry, RuntimeSurface } from "@/types/configSchema";
import { Header } from "@/components/layout/Header";
import { AutonomyPanel } from "./AutonomyPanel";
import { FeatureFlagsPanel } from "./FeatureFlagsPanel";
import { OrgProfilePanel } from "./OrgProfilePanel";
import { SafelistPanel } from "./SafelistPanel";
import { SessionRevocationPanel } from "./SessionRevocationPanel";
import { RetentionPanel } from "./RetentionPanel";
import { Card, CardContent } from "@/components/ds/card";
import { Input } from "@/components/ds/input";
import { Button } from "@/components/ds/button";

const SCOPE_BADGE: Record<string, string> = {
  org: "border-sky-500/40 text-sky-300",
  user: "border-emerald-500/40 text-emerald-300",
  global: "border-amber-500/40 text-amber-300",
};

function renderValue(entry: DeployTimeEntry): string {
  if (entry.sensitive) return "•••";
  const v = entry.value;
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function SurfaceCard({ surface }: { surface: RuntimeSurface }) {
  const internalLink = surface.ui && surface.ui.startsWith("/") ? surface.ui.split(" ")[0] : null;
  return (
    <Card data-testid={`config-surface-${surface.key}`}>
      <CardContent className="py-4 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-semibold">{surface.title}</span>
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
              SCOPE_BADGE[surface.scope] ?? "border-border text-muted-foreground"
            }`}
            data-testid={`config-surface-${surface.key}-scope`}
          >
            {surface.scope}
          </span>
        </div>
        <p className="text-xs text-muted-foreground">{surface.description}</p>
        <div className="flex items-center justify-between gap-2 text-xs">
          <span className="inline-flex items-center gap-1 text-muted-foreground">
            <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
            {surface.write_permission ?? "self-scoped"}
          </span>
          {internalLink ? (
            <Link
              to={internalLink}
              className="inline-flex items-center gap-1 text-primary hover:underline"
              data-testid={`config-surface-${surface.key}-link`}
            >
              Open
              <ExternalLink className="w-3 h-3" aria-hidden="true" />
            </Link>
          ) : (
            <span className="text-muted-foreground/70">
              {surface.api ? surface.ui : "no runtime editor yet"}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Configuration Center (#418 slice 2): renders the consolidated inventory
 * from GET /config/schema — runtime-changeable surfaces as navigable cards,
 * deploy-time BTAGENT_* knobs as a read-only reference table with secret
 * values redacted server-side.
 */
export function ConfigCenterPage() {
  const [schema, setSchema] = useState<ConfigSchema | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const load = () => {
    setError(null);
    getConfigSchema()
      .then(setSchema)
      .catch(() => setError("Could not load the configuration inventory"));
  };

  useEffect(load, []);

  const filteredEnv = useMemo(() => {
    if (!schema) return [];
    const q = filter.trim().toLowerCase();
    if (!q) return schema.deploy_time;
    return schema.deploy_time.filter(
      (e) => e.env.toLowerCase().includes(q) || e.field.toLowerCase().includes(q),
    );
  }, [schema, filter]);

  return (
    <>
      <Header title="Configuration Center" />
      <div className="flex-1 overflow-y-auto p-6 space-y-8" data-testid="config-center">
        {error ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            role="alert"
            data-testid="config-center-error"
          >
            <AlertTriangle className="w-10 h-10 text-severity-medium mb-3" aria-hidden="true" />
            <p className="text-sm">{error}</p>
            <Button variant="ghost" size="sm" onClick={load} className="mt-3">
              Retry
            </Button>
          </div>
        ) : !schema ? (
          <div
            className="flex items-center justify-center py-20"
            data-testid="config-center-loading"
          >
            <Loader2
              className="w-8 h-8 text-muted-foreground animate-spin"
              aria-label="Loading configuration inventory"
            />
          </div>
        ) : (
          <>
            <section>
              <div className="flex items-center gap-2 mb-3">
                <SlidersHorizontal className="w-4 h-4 text-primary" aria-hidden="true" />
                <h2 className="text-sm font-semibold">Runtime settings</h2>
                <span className="text-xs text-muted-foreground">
                  changeable in-app, per scope
                </span>
              </div>
              <div
                className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"
                data-testid="config-center-runtime"
              >
                {schema.runtime.map((surface) => (
                  <SurfaceCard key={surface.key} surface={surface} />
                ))}
              </div>
            </section>

            {/* Organisation profile (#418 / GH #393) — admin-editable
             * context injected into agent prompts; hides itself if its
             * fetch fails. */}
            <OrgProfilePanel />

            {/* Autonomy & HITL gates (#418 slices 3+8) — self-contained
             * panel with admin editing; hides itself if its fetch fails. */}
            <AutonomyPanel />

            {/* Per-org capability toggles (#418 slice 5) — self-contained
             * panel; hides itself if its fetch fails. */}
            <FeatureFlagsPanel />

            {/* Never-block safelist (#106) — the guard that refuses
             * containment. Reads need containment:execute, so this hides
             * itself for everyone below incident commander. */}
            <SafelistPanel />

            {/* Users & sessions (#142) — the org roster and admin session
             * revocation. Both need user:edit, so this hides itself for
             * everyone below admin. */}
            <SessionRevocationPanel />

            {/* Data retention (#418) — posture plus the destructive manual
             * cleanup (admin). Hides itself if its fetch fails. */}
            <RetentionPanel />

            <section>
              <div className="flex flex-col md:flex-row md:items-center gap-2 mb-3">
                <h2 className="text-sm font-semibold">Deploy-time settings</h2>
                <span className="text-xs text-muted-foreground flex-1">
                  BTAGENT_* environment knobs — read-only; secret values never leave the
                  server
                </span>
                <Input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter by name…"
                  aria-label="Filter deploy-time settings"
                  data-testid="config-center-env-filter"
                  className="md:w-64 h-9"
                />
              </div>
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-xs" data-testid="config-center-env-table">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="px-3 py-2 font-medium">Env var</th>
                      <th className="px-3 py-2 font-medium">Type</th>
                      <th className="px-3 py-2 font-medium">Value</th>
                      <th className="px-3 py-2 font-medium">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {filteredEnv.map((entry) => (
                      <tr key={entry.field} data-testid={`config-env-${entry.field}`}>
                        <td className="px-3 py-2 font-mono">{entry.env}</td>
                        <td className="px-3 py-2 text-muted-foreground">{entry.type}</td>
                        <td className="px-3 py-2 font-mono max-w-md truncate">
                          {entry.sensitive ? (
                            <span
                              className="inline-flex items-center gap-1 text-muted-foreground"
                              data-testid={`config-env-${entry.field}-redacted`}
                            >
                              <EyeOff className="w-3 h-3" aria-hidden="true" />
                              redacted
                            </span>
                          ) : (
                            renderValue(entry)
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={
                              entry.is_default
                                ? "text-muted-foreground/70"
                                : "text-amber-300"
                            }
                          >
                            {entry.is_default ? "default" : "configured"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredEnv.length === 0 && (
                  <p
                    className="p-4 text-xs text-muted-foreground"
                    data-testid="config-center-env-empty"
                  >
                    No settings match the filter.
                  </p>
                )}
              </div>
            </section>
          </>
        )}
      </div>
    </>
  );
}
