import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Pencil,
  Plus,
  Rss,
  Trash2,
  X,
} from "lucide-react";
import { ApiError } from "@/api/client";
import {
  createTaxiiFeed,
  deleteTaxiiFeed,
  listTaxiiFeeds,
  updateTaxiiFeed,
  MAX_POLL_INTERVAL_MINUTES,
  MIN_POLL_INTERVAL_MINUTES,
  type CreateTaxiiFeedRequest,
  type TaxiiAuthStyle,
  type TaxiiFeed,
  type UpdateTaxiiFeedRequest,
} from "@/api/taxii";
import { Badge } from "@/components/ds/badge";
import { Button } from "@/components/ds/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

/**
 * Pull a human-readable message out of an ApiError body.
 *
 * The server owns what counts as a valid feed — URL shape, the
 * reference-only secret rule, the poll-interval bounds — so its refusal text
 * is shown verbatim rather than replaced with a generic "save failed". Handles
 * both detail shapes: our service errors raise ``HTTPException(422, "…")``
 * (a string), while FastAPI's own request validation returns a list of
 * ``{loc, msg}`` objects.
 */
function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: unknown } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (Array.isArray(detail)) {
      const msgs = detail
        .map((d) =>
          d && typeof d === "object" && typeof (d as { msg?: unknown }).msg === "string"
            ? (d as { msg: string }).msg
            : null,
        )
        .filter((m): m is string => Boolean(m));
      if (msgs.length > 0) return msgs.join("; ");
    }
  }
  return fallback;
}

function formatWhen(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  return d.toLocaleString();
}

/**
 * A single ``${secret:...}`` / ``${env:VAR}`` / ``${LEGACY_VAR}`` reference —
 * the same shape ``btagent_shared.utils.secrets.SECRET_PATTERN`` matches in
 * full. Kept identical to the Integrations credential panel so the two
 * reference fields can't disagree about what a reference looks like. This is a
 * courtesy check only: the server re-validates and its 422 is what's shown.
 */
const REFERENCE_RE =
  /^\$\{(?:secret:(?:vault|aws|keyring):[^}#]+(?:#[^}]+)?|env:[^}]+|[A-Z_][A-Z0-9_]*)\}$/;

const AUTH_STYLES: TaxiiAuthStyle[] = ["none", "bearer", "basic"];

interface FormState {
  name: string;
  server_url: string;
  collection_id: string;
  auth_style: TaxiiAuthStyle;
  auth_secret_ref: string;
  poll_interval_minutes: string;
  enabled: boolean;
}

const EMPTY_FORM: FormState = {
  name: "",
  server_url: "",
  collection_id: "",
  auth_style: "none",
  auth_secret_ref: "",
  poll_interval_minutes: "60",
  enabled: true,
};

function formFromFeed(feed: TaxiiFeed): FormState {
  return {
    name: feed.name,
    server_url: feed.server_url,
    collection_id: feed.collection_id,
    auth_style: feed.auth_style,
    // The stored value is a reference — a Vault path / env var name, i.e.
    // config. Echoing it back is safe and necessary to edit the row; the
    // material it names is never fetched, resolved or displayed anywhere.
    auth_secret_ref: feed.auth_secret_ref,
    poll_interval_minutes: String(feed.poll_interval_minutes),
    enabled: feed.enabled,
  };
}

function toRequest(form: FormState): CreateTaxiiFeedRequest {
  return {
    name: form.name.trim(),
    server_url: form.server_url.trim(),
    collection_id: form.collection_id.trim(),
    auth_style: form.auth_style,
    // "none" forces the ref empty server-side; send it empty so a leftover
    // keystroke can't turn a no-auth feed into a 422.
    auth_secret_ref:
      form.auth_style === "none" ? "" : form.auth_secret_ref.trim(),
    poll_interval_minutes: Number(form.poll_interval_minutes),
    enabled: form.enabled,
  };
}

/**
 * Only the fields that actually changed.
 *
 * The PATCH route is ``exclude_unset``, and every write lands in the audit
 * ledger as ``{"fields": [...]}``. Posting the whole form would record a
 * seven-field change for a one-field edit, so the diff is what keeps that
 * ledger entry honest. Returns ``null`` when nothing changed — the server
 * rightly 422s an empty patch, and there is no point asking it to.
 *
 * ``auth_secret_ref`` falls out of the same comparison: flipping the style to
 * "none" blanks the ref in ``toRequest``, which then differs from the stored
 * value and is therefore sent — exactly what the server's pair validation
 * requires.
 */
function diffRequest(
  feed: TaxiiFeed,
  form: FormState,
): UpdateTaxiiFeedRequest | null {
  const next = toRequest(form);
  const current: CreateTaxiiFeedRequest = {
    name: feed.name,
    server_url: feed.server_url,
    collection_id: feed.collection_id,
    auth_style: feed.auth_style,
    auth_secret_ref: feed.auth_secret_ref,
    poll_interval_minutes: feed.poll_interval_minutes,
    enabled: feed.enabled,
  };
  const changed: UpdateTaxiiFeedRequest = {};
  for (const key of Object.keys(current) as (keyof CreateTaxiiFeedRequest)[]) {
    if (next[key] !== current[key]) {
      // Each assignment is key-matched by construction; the cast is only
      // needed because TS can't see that through the loop variable.
      (changed as Record<string, unknown>)[key] = next[key];
    }
  }
  return Object.keys(changed).length > 0 ? changed : null;
}

function StatusBadge({ feed }: { feed: TaxiiFeed }) {
  if (feed.last_status === "error") {
    return (
      <Badge variant="destructive" data-testid={`taxii-status-${feed.id}`}>
        <AlertTriangle className="mr-1 h-3 w-3" aria-hidden="true" />
        poll failed
      </Badge>
    );
  }
  if (feed.last_status === "ok") {
    return (
      <Badge variant="low" data-testid={`taxii-status-${feed.id}`}>
        <CheckCircle2 className="mr-1 h-3 w-3" aria-hidden="true" />
        polled ok
      </Badge>
    );
  }
  return (
    <Badge variant="medium" data-testid={`taxii-status-${feed.id}`}>
      never polled
    </Badge>
  );
}

/** The create / edit form. ``feed`` present means edit, absent means create. */
function FeedForm({
  feed,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  feed: TaxiiFeed | null;
  busy: boolean;
  error: string | null;
  onSubmit: (form: FormState) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState<FormState>(
    feed ? formFromFeed(feed) : EMPTY_FORM,
  );
  const suffix = feed ? feed.id : "new";
  const needsRef = form.auth_style !== "none";
  const refText = form.auth_secret_ref.trim();
  const refLooksWrong = needsRef && refText !== "" && !REFERENCE_RE.test(refText);

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }));

  return (
    <form
      className="mt-3 space-y-2 rounded-md border border-border bg-card/50 p-3"
      data-testid={`taxii-feed-form-${suffix}`}
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(form);
      }}
    >
      <div className="grid gap-2 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">Name</span>
          <Input
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="CISA AIS indicators"
            className="h-9"
            data-testid={`taxii-form-name-${suffix}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">TAXII 2.1 api-root URL</span>
          <Input
            value={form.server_url}
            onChange={(e) => set("server_url", e.target.value)}
            placeholder="https://taxii.example.test/api1"
            className="h-9 font-mono"
            spellCheck={false}
            data-testid={`taxii-form-server-url-${suffix}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">Collection id</span>
          <Input
            value={form.collection_id}
            onChange={(e) => set("collection_id", e.target.value)}
            placeholder="91a7b528-80eb-42ed-a74d-c6fbd5a26116"
            className="h-9 font-mono"
            spellCheck={false}
            data-testid={`taxii-form-collection-${suffix}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">
            Poll interval (minutes, {MIN_POLL_INTERVAL_MINUTES}–
            {MAX_POLL_INTERVAL_MINUTES})
          </span>
          <Input
            value={form.poll_interval_minutes}
            onChange={(e) => set("poll_interval_minutes", e.target.value)}
            inputMode="numeric"
            className="h-9"
            data-testid={`taxii-form-interval-${suffix}`}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-muted-foreground">Auth style</span>
          <NativeSelect
            value={form.auth_style}
            onChange={(e) => set("auth_style", e.target.value as TaxiiAuthStyle)}
            className="h-9"
            data-testid={`taxii-form-auth-style-${suffix}`}
          >
            {AUTH_STYLES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </NativeSelect>
        </label>
        {needsRef && (
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">
              Auth secret <em>reference</em>
            </span>
            <Input
              value={form.auth_secret_ref}
              onChange={(e) => set("auth_secret_ref", e.target.value)}
              placeholder="${secret:vault:taxii/cisa#token} or ${env:TAXII_TOKEN}"
              className="h-9 font-mono"
              spellCheck={false}
              autoComplete="off"
              data-testid={`taxii-form-auth-ref-${suffix}`}
            />
          </label>
        )}
      </div>

      {needsRef && (
        <p
          className="text-xs text-muted-foreground"
          data-testid={`taxii-form-secret-hint-${suffix}`}
        >
          Paste a <span className="font-mono">${"{"}secret:vault:…{"}"}</span>,{" "}
          <span className="font-mono">${"{"}secret:aws:…{"}"}</span> or{" "}
          <span className="font-mono">${"{"}env:VAR{"}"}</span> reference — never
          the token itself. The credential stays in Vault / AWS Secrets Manager /
          env and is resolved only at poll time; a raw value is refused by the
          server and is never displayed here.
        </p>
      )}

      {refLooksWrong && (
        <p
          className="text-xs text-severity-medium"
          role="alert"
          data-testid={`taxii-form-ref-invalid-${suffix}`}
        >
          That is not a reference. Use exactly one ${"{"}secret:…{"}"} /{" "}
          ${"{"}env:VAR{"}"} token.
        </p>
      )}

      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          checked={form.enabled}
          onChange={(e) => set("enabled", e.target.checked)}
          data-testid={`taxii-form-enabled-${suffix}`}
        />
        Enabled — the 15-minute sweep polls this feed when its interval is due
      </label>

      {error && (
        <p
          className="text-xs text-destructive"
          role="alert"
          data-testid={`taxii-form-error-${suffix}`}
        >
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          disabled={busy}
          data-testid={`taxii-form-save-${suffix}`}
        >
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin" aria-label="Saving" />
          ) : feed ? (
            "Save changes"
          ) : (
            "Create feed"
          )}
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={onCancel}
          data-testid={`taxii-form-cancel-${suffix}`}
        >
          <X className="mr-1 h-4 w-4" aria-hidden="true" />
          Cancel
        </Button>
      </div>
    </form>
  );
}

/**
 * Settings → Integrations panel for TAXII 2.1 feed subscriptions (#105 / UC-2.1).
 *
 * The pull half of "STIX/TAXII feeds" shipped backend-only: an org-scoped
 * config store, RBAC-gated CRUD and a 15-minute poll sweep with no way to see
 * or change any of it. An operator could not tell a feed that had never polled
 * from one failing every 15 minutes. This is that screen.
 *
 * Gating mirrors the API exactly rather than re-deciding it:
 * ``taxii:view`` (senior_analyst+) to read, ``taxii:manage`` (admin) to write.
 * A role below senior_analyst gets a 403 on the list call and the panel hides
 * itself, the same self-effacing convention the other config panels use; a
 * senior_analyst / incident_commander sees the feeds and their telemetry with
 * no create / edit / delete controls rendered at all. The server is still the
 * enforcement point — hiding a button is presentation, not security.
 *
 * ``auth_secret_ref`` holds a reference, never material. Nothing here resolves
 * one, and the field's help text says so, because a field that merely *looks*
 * like a password box is an invitation to paste a token into the database.
 */
export function TaxiiFeedsPanel() {
  const [feeds, setFeeds] = useState<TaxiiFeed[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [enabledOnly, setEnabledOnly] = useState(false);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(
    null,
  );
  const [rowError, setRowError] = useState<string | null>(null);

  const role = useAuthStore((s) => s.user?.role);
  // taxii:manage is admin-only; taxii:view is senior_analyst and above, which
  // by the backend's role hierarchy includes incident_commander.
  const canManage = role === UserRole.ADMIN;
  const canView =
    role === UserRole.ADMIN ||
    role === UserRole.INCIDENT_COMMANDER ||
    role === UserRole.SENIOR_ANALYST;

  const load = useCallback(
    async (onlyEnabled: boolean) => {
      if (!canView) {
        setFeeds(null);
        setForbidden(true);
        setLoading(false);
        return;
      }
      setLoading(true);
      setLoadError(null);
      try {
        const resp = await listTaxiiFeeds(
          onlyEnabled ? { enabledOnly: true } : undefined,
        );
        setFeeds(resp.items);
        setForbidden(false);
      } catch (e) {
        // A 403 means this role can't read feeds — that's a gate doing its
        // job, not an error worth shouting about, so the panel disappears.
        if (e instanceof ApiError && e.status === 403) {
          setForbidden(true);
          setFeeds(null);
        } else {
          setLoadError(errMessage(e, "Could not load TAXII feeds"));
        }
      } finally {
        setLoading(false);
      }
    },
    [canView],
  );

  useEffect(() => {
    void load(enabledOnly);
  }, [load, enabledOnly]);

  const handleCreate = useCallback(
    async (form: FormState) => {
      setBusy(true);
      setFormError(null);
      try {
        await createTaxiiFeed(toRequest(form));
        setCreating(false);
        await load(enabledOnly);
      } catch (e) {
        setFormError(errMessage(e, "Could not create the feed"));
      } finally {
        setBusy(false);
      }
    },
    [enabledOnly, load],
  );

  const handleUpdate = useCallback(
    async (feed: TaxiiFeed, form: FormState) => {
      const changes = diffRequest(feed, form);
      if (changes === null) {
        setEditingId(null);
        setFormError(null);
        return;
      }
      setBusy(true);
      setFormError(null);
      try {
        await updateTaxiiFeed(feed.id, changes);
        setEditingId(null);
        await load(enabledOnly);
      } catch (e) {
        setFormError(errMessage(e, "Could not update the feed"));
      } finally {
        setBusy(false);
      }
    },
    [enabledOnly, load],
  );

  const handleDelete = useCallback(
    async (feedId: string) => {
      setBusy(true);
      setRowError(null);
      try {
        await deleteTaxiiFeed(feedId);
        setConfirmingDeleteId(null);
        await load(enabledOnly);
      } catch (e) {
        setRowError(errMessage(e, "Could not delete the feed"));
      } finally {
        setBusy(false);
      }
    },
    [enabledOnly, load],
  );

  // Below senior_analyst there is nothing to show and the API would 403.
  if (forbidden) return null;

  return (
    <Card data-testid="taxii-feeds-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Rss className="h-4 w-4" aria-hidden="true" />
          TAXII 2.1 feeds
          <span
            className="text-xs font-normal text-muted-foreground"
            data-testid="taxii-feed-count"
          >
            {feeds?.length ?? 0} subscription
            {(feeds?.length ?? 0) === 1 ? "" : "s"}
          </span>
        </CardTitle>
        <CardDescription>
          Org-scoped collection subscriptions. A sweep runs every 15 minutes and
          polls each enabled feed whose interval is due, ingesting objects
          through the STIX path so TLP comes from each object&rsquo;s own
          markings. Credentials are referenced, never stored here.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              data-testid="taxii-filter-enabled-only"
            />
            Enabled only
          </label>
          {canManage && !creating && (
            <Button
              size="sm"
              onClick={() => {
                setCreating(true);
                setEditingId(null);
                setFormError(null);
              }}
              data-testid="taxii-feed-add"
            >
              <Plus className="mr-1 h-4 w-4" aria-hidden="true" />
              Add feed
            </Button>
          )}
        </div>

        {loading && (
          <div
            className="flex items-center gap-2 text-sm text-muted-foreground"
            data-testid="taxii-feeds-loading"
          >
            <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            Loading TAXII feeds…
          </div>
        )}

        {loadError && (
          <p
            className="text-sm text-destructive"
            role="alert"
            data-testid="taxii-feeds-error"
          >
            {loadError}
          </p>
        )}

        {creating && canManage && (
          <FeedForm
            feed={null}
            busy={busy}
            error={formError}
            onSubmit={(form) => void handleCreate(form)}
            onCancel={() => {
              setCreating(false);
              setFormError(null);
            }}
          />
        )}

        {!loading && !loadError && feeds !== null && feeds.length === 0 && (
          <p
            className="text-sm text-muted-foreground"
            data-testid="taxii-feeds-empty"
          >
            {enabledOnly
              ? "No enabled feeds."
              : "No TAXII feeds configured for this org."}
          </p>
        )}

        {!loadError &&
          (feeds ?? []).map((feed) => (
            <div
              key={feed.id}
              className="rounded-md border border-border bg-card/50 p-3"
              data-testid={`taxii-feed-row-${feed.id}`}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{feed.name}</span>
                    <Badge
                      variant={feed.enabled ? "low" : "medium"}
                      data-testid={`taxii-enabled-${feed.id}`}
                    >
                      {feed.enabled ? "enabled" : "disabled"}
                    </Badge>
                    <StatusBadge feed={feed} />
                    <Badge variant="low">auth:{feed.auth_style}</Badge>
                    <Badge variant="low">every {feed.poll_interval_minutes}m</Badge>
                  </div>
                  <p className="break-all font-mono text-xs text-muted-foreground">
                    {feed.server_url} · {feed.collection_id}
                  </p>
                  {feed.auth_style !== "none" && (
                    <p
                      className="break-all font-mono text-xs text-muted-foreground"
                      data-testid={`taxii-secret-ref-${feed.id}`}
                    >
                      secret ref: {feed.auth_secret_ref}
                    </p>
                  )}
                </div>
                {canManage && (
                  <div className="flex shrink-0 items-center gap-2">
                    {confirmingDeleteId === feed.id ? (
                      <>
                        <span className="text-xs text-severity-medium">
                          Delete this subscription?
                        </span>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={busy}
                          onClick={() => void handleDelete(feed.id)}
                          data-testid={`taxii-delete-confirm-${feed.id}`}
                        >
                          Delete
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={busy}
                          onClick={() => setConfirmingDeleteId(null)}
                          data-testid={`taxii-delete-cancel-${feed.id}`}
                        >
                          Cancel
                        </Button>
                      </>
                    ) : (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          onClick={() => {
                            setEditingId(
                              editingId === feed.id ? null : feed.id,
                            );
                            setCreating(false);
                            setFormError(null);
                          }}
                          data-testid={`taxii-edit-${feed.id}`}
                        >
                          <Pencil className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={busy}
                          onClick={() => {
                            setConfirmingDeleteId(feed.id);
                            setRowError(null);
                          }}
                          data-testid={`taxii-delete-${feed.id}`}
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </Button>
                      </>
                    )}
                  </div>
                )}
              </div>

              {/* Poll telemetry — the whole reason this panel exists. */}
              <dl
                className="mt-2 grid gap-x-4 gap-y-1 border-t border-border/50 pt-2 text-xs sm:grid-cols-2"
                data-testid={`taxii-telemetry-${feed.id}`}
              >
                <div className="flex gap-1">
                  <dt className="text-muted-foreground">Last polled:</dt>
                  <dd>{formatWhen(feed.last_polled_at)}</dd>
                </div>
                <div className="flex gap-1">
                  <dt className="text-muted-foreground">Objects ingested:</dt>
                  <dd>{feed.objects_ingested.toLocaleString()}</dd>
                </div>
                <div className="flex min-w-0 gap-1">
                  <dt className="text-muted-foreground">Cursor:</dt>
                  <dd className="truncate font-mono">
                    {feed.last_cursor ?? "none — next poll starts from scratch"}
                  </dd>
                </div>
                <div className="flex gap-1">
                  <dt className="text-muted-foreground">Intake case:</dt>
                  <dd className="font-mono">
                    {feed.intake_investigation_id ?? "not provisioned yet"}
                  </dd>
                </div>
              </dl>

              {feed.last_error && (
                <p
                  className="mt-2 flex items-start gap-1.5 text-xs text-destructive"
                  data-testid={`taxii-last-error-${feed.id}`}
                >
                  <AlertTriangle
                    className="mt-0.5 h-3.5 w-3.5 shrink-0"
                    aria-hidden="true"
                  />
                  <span>{feed.last_error}</span>
                </p>
              )}

              {rowError && confirmingDeleteId === feed.id && (
                <p
                  className="mt-2 text-xs text-destructive"
                  role="alert"
                  data-testid={`taxii-row-error-${feed.id}`}
                >
                  {rowError}
                </p>
              )}

              {editingId === feed.id && canManage && (
                <FeedForm
                  feed={feed}
                  busy={busy}
                  error={formError}
                  onSubmit={(form) => void handleUpdate(feed, form)}
                  onCancel={() => {
                    setEditingId(null);
                    setFormError(null);
                  }}
                />
              )}
            </div>
          ))}

        {!canManage && feeds !== null && (
          <p
            className="text-xs text-muted-foreground"
            data-testid="taxii-readonly-note"
          >
            Read-only — the admin role (<span className="font-mono">taxii:manage</span>
            ) is required to add, edit or remove feed subscriptions.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
