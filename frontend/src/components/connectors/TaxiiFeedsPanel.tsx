/**
 * TAXII 2.1 feed subscriptions panel (#105 / UC-2.1) — the admin screen the
 * backend feed store shipped without. Lives on Settings → Integrations next
 * to the connector catalog.
 *
 * RBAC mirrors the API: taxii:view (senior_analyst+) to read — the panel
 * self-effaces below that — and taxii:manage (admin) for the add form,
 * enable/disable toggle and delete. `auth_secret_ref` is a `${secret:...}` /
 * `${env:VAR}` REFERENCE; the server rejects raw credential material with a
 * 422 that this panel surfaces verbatim rather than flattening.
 *
 * Poll telemetry (last status/error, objects ingested, last polled) is shown
 * per feed so a silently-failing feed is visible, not mysterious.
 */
import { useCallback, useEffect, useState } from "react";
import { Loader2, Rss, Trash2 } from "lucide-react";

import {
  createTaxiiFeed,
  deleteTaxiiFeed,
  listTaxiiFeeds,
  updateTaxiiFeed,
  type TaxiiFeed,
} from "@/api/taxii";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ds/button";
import { NativeSelect } from "@/components/ds/native-select";
import { useAuthStore } from "@/stores/authStore";
import { UserRole, roleAtLeast } from "@/types/config";

function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (detail !== undefined) return JSON.stringify(detail);
  }
  return fallback;
}

function statusTone(feed: TaxiiFeed): string {
  if (!feed.enabled) return "text-slate-500";
  if (feed.last_status === "error") return "text-amber-400";
  if (feed.last_status === "ok") return "text-emerald-400";
  return "text-slate-400";
}

export function TaxiiFeedsPanel() {
  const role = useAuthStore((s) => s.user?.role);
  // F10: hierarchical, matching the API's taxii:view (senior_analyst+) —
  // incident_commander outranks senior_analyst and must see the panel too.
  const canView = roleAtLeast(role, UserRole.SENIOR_ANALYST);
  const canManage = roleAtLeast(role, UserRole.ADMIN);

  const [feeds, setFeeds] = useState<TaxiiFeed[] | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Add-feed form (admin only).
  const [name, setName] = useState("");
  const [serverUrl, setServerUrl] = useState("");
  const [collectionId, setCollectionId] = useState("");
  const [authStyle, setAuthStyle] = useState("none");
  const [secretRef, setSecretRef] = useState("");
  const [pollMinutes, setPollMinutes] = useState("60");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    try {
      const resp = await listTaxiiFeeds();
      setFeeds(resp.items);
    } catch {
      // Self-effacing on failure, matching the panel convention.
      setFeeds(null);
    }
  }, []);

  useEffect(() => {
    if (canView) void load();
  }, [canView, load]);

  if (!canView || feeds === null) return null;

  const handleCreate = async () => {
    setCreating(true);
    setError(null);
    try {
      await createTaxiiFeed({
        name: name.trim(),
        server_url: serverUrl.trim(),
        collection_id: collectionId.trim(),
        auth_style: authStyle,
        auth_secret_ref: secretRef.trim(),
        poll_interval_minutes: Number(pollMinutes) || 60,
      });
      setName("");
      setServerUrl("");
      setCollectionId("");
      setSecretRef("");
      await load();
    } catch (e) {
      // The contentful refusal here is the raw-credential 422 — show it as-is.
      setError(errMessage(e, "Failed to create feed."));
    } finally {
      setCreating(false);
    }
  };

  const handleToggle = async (feed: TaxiiFeed) => {
    setBusyId(feed.id);
    setError(null);
    try {
      await updateTaxiiFeed(feed.id, { enabled: !feed.enabled });
      await load();
    } catch (e) {
      setError(errMessage(e, "Failed to update feed."));
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (feedId: string) => {
    // Two-step: the first click arms, the second deletes.
    if (confirmDeleteId !== feedId) {
      setConfirmDeleteId(feedId);
      return;
    }
    setBusyId(feedId);
    setError(null);
    try {
      await deleteTaxiiFeed(feedId);
      setConfirmDeleteId(null);
      await load();
    } catch (e) {
      setError(errMessage(e, "Failed to delete feed."));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section
      className="rounded-lg border border-border bg-card/50 p-4"
      data-testid="taxii-feeds-panel"
    >
      <div className="mb-2 flex items-center gap-2">
        <Rss className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">TAXII feeds</h2>
        <span className="text-xs text-muted-foreground">
          scheduled STIX intake — TLP derives from each object&apos;s markings
        </span>
      </div>

      {feeds.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="taxii-feeds-empty">
          No feeds configured. TAXII collections are polled on their interval and
          ingested through the STIX pipeline.
        </p>
      ) : (
        <ul className="space-y-2" data-testid="taxii-feeds-list">
          {feeds.map((feed) => (
            <li
              key={feed.id}
              className="rounded-md border border-slate-800 bg-slate-800/40 px-3 py-2 text-sm"
              data-testid={`taxii-feed-${feed.id}`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-slate-200">{feed.name}</span>
                <span className="break-all font-mono text-xs text-slate-400">
                  {feed.server_url} · {feed.collection_id}
                </span>
                <span className={`text-xs ${statusTone(feed)}`} data-testid="taxii-feed-status">
                  {feed.enabled ? feed.last_status || "pending first poll" : "disabled"}
                </span>
                <span className="text-xs text-slate-500">
                  every {feed.poll_interval_minutes}m · {feed.objects_ingested} objects
                  {feed.last_polled_at
                    ? ` · last ${new Date(feed.last_polled_at).toLocaleString()}`
                    : ""}
                </span>
                {canManage && (
                  <span className="ml-auto flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busyId === feed.id}
                      onClick={() => void handleToggle(feed)}
                      data-testid={`taxii-feed-toggle-${feed.id}`}
                    >
                      {feed.enabled ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busyId === feed.id}
                      onClick={() => void handleDelete(feed.id)}
                      data-testid={`taxii-feed-delete-${feed.id}`}
                    >
                      <Trash2 className="mr-1 h-3.5 w-3.5" />
                      {confirmDeleteId === feed.id ? "Confirm delete" : "Delete"}
                    </Button>
                  </span>
                )}
              </div>
              {feed.enabled && feed.last_status === "error" && feed.last_error && (
                <p className="mt-1 text-xs text-amber-400" data-testid="taxii-feed-error">
                  {feed.last_error}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}

      {canManage && (
        <div className="mt-4 space-y-2" data-testid="taxii-feed-form">
          <p className="text-xs text-muted-foreground">
            Credentials are bound by <span className="font-mono">${"{secret:...}"}</span> /{" "}
            <span className="font-mono">${"{env:VAR}"}</span> reference only — raw material
            is rejected.
          </p>
          <div className="flex flex-wrap gap-2">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Feed name"
              aria-label="Feed name"
              data-testid="taxii-feed-name"
              className="h-9 w-44 rounded-md border border-border bg-background px-3 text-xs"
            />
            <input
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              placeholder="TAXII api-root URL"
              aria-label="Server URL"
              data-testid="taxii-feed-url"
              className="h-9 min-w-64 flex-1 rounded-md border border-border bg-background px-3 text-xs"
            />
            <input
              value={collectionId}
              onChange={(e) => setCollectionId(e.target.value)}
              placeholder="Collection id"
              aria-label="Collection id"
              data-testid="taxii-feed-collection"
              className="h-9 w-44 rounded-md border border-border bg-background px-3 text-xs"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <NativeSelect
              value={authStyle}
              onChange={(e) => setAuthStyle(e.target.value)}
              aria-label="Auth style"
              data-testid="taxii-feed-auth-style"
              className="h-9 w-32"
            >
              <option value="none">No auth</option>
              <option value="bearer">Bearer</option>
              <option value="basic">Basic</option>
            </NativeSelect>
            <input
              value={secretRef}
              onChange={(e) => setSecretRef(e.target.value)}
              placeholder="${secret:vault:cti/taxii} (reference only)"
              aria-label="Credential reference"
              data-testid="taxii-feed-secret-ref"
              className="h-9 min-w-64 flex-1 rounded-md border border-border bg-background px-3 font-mono text-xs"
            />
            <input
              value={pollMinutes}
              onChange={(e) => setPollMinutes(e.target.value)}
              type="number"
              min={5}
              aria-label="Poll interval minutes"
              data-testid="taxii-feed-interval"
              className="h-9 w-28 rounded-md border border-border bg-background px-3 text-xs"
            />
            <Button
              size="sm"
              disabled={creating || !name.trim() || !serverUrl.trim() || !collectionId.trim()}
              onClick={() => void handleCreate()}
              data-testid="taxii-feed-create"
            >
              {creating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Add feed
            </Button>
          </div>
        </div>
      )}

      {error && (
        <p
          className="mt-2 text-xs text-severity-medium"
          role="alert"
          data-testid="taxii-feeds-error"
        >
          {error}
        </p>
      )}
    </section>
  );
}
