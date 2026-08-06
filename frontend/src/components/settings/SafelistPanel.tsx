import { useEffect, useState } from "react";
import { Loader2, Plus, ShieldOff, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  addSafelistEntry,
  listSafelistEntries,
  removeSafelistEntry,
  type SafelistEntry,
} from "@/api/containment";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";
import {
  SAFELIST_ENTRY_TYPE_LABELS,
  type SafelistEntryType,
} from "@/types/containment";

/** Pull a human-readable message out of an ApiError's JSON ``detail`` body. */
function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: string } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
  }
  return fallback;
}

/**
 * Org never-block safelist manager (#106). The safelist is what *stops*
 * containment: a matching target is refused before any block dispatch. Until
 * now it had no UI at all — an incident commander could execute containment
 * from the response plan but could not see, let alone correct, the guard that
 * silently refused it.
 *
 * Reads and writes both require ``containment:execute`` (incident_commander+),
 * so for everyone else the GET 403s and the panel hides itself entirely —
 * the same self-effacing convention the other Configuration Center panels use.
 *
 * Validation is deliberately NOT duplicated here beyond "non-blank": the
 * server owns what counts as a valid IP or domain (``normalize_entry``) and
 * its 422 detail is shown verbatim, so the two can't drift apart.
 */
export function SafelistPanel() {
  const [entries, setEntries] = useState<SafelistEntry[] | null>(null);
  const [entryType, setEntryType] = useState<SafelistEntryType>("ip");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Two-step removal: holds the id awaiting confirmation. Dropping a
  // never-block guard is the permissive direction — it re-enables containment
  // against something someone deliberately protected — so it shouldn't be a
  // single stray click.
  const [confirmingId, setConfirmingId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listSafelistEntries()
      .then((rows) => {
        if (!cancelled) setEntries(rows);
      })
      .catch(() => {
        if (!cancelled) setEntries(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (entries === null) return null;

  const handleAdd = async () => {
    const v = value.trim();
    const why = reason.trim();
    if (!v) {
      setFormError("Enter the IP or domain that must never be blocked.");
      return;
    }
    if (!why) {
      // Not a server constraint — an unexplained never-block entry is
      // un-auditable six months later, so the form insists on a reason.
      setFormError("Give a reason — a future responder needs to know why this is protected.");
      return;
    }
    setFormError(null);
    setBusy(true);
    try {
      const created = await addSafelistEntry({ entryType, value: v, reason: why });
      setEntries((prev) => {
        const rest = (prev ?? []).filter((e) => e.id !== created.id);
        return [created, ...rest];
      });
      setValue("");
      setReason("");
    } catch (e) {
      setFormError(errMessage(e, "Could not add the safelist entry"));
    } finally {
      setBusy(false);
    }
  };

  const handleRemove = async (entry: SafelistEntry) => {
    setBusy(true);
    try {
      await removeSafelistEntry(entry.id);
      setEntries((prev) => (prev ?? []).filter((e) => e.id !== entry.id));
      setConfirmingId(null);
      toast.success(`${entry.value} can be contained again`);
    } catch (e) {
      toast.error(errMessage(e, "Could not remove the safelist entry"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section data-testid="safelist-panel">
      <div className="flex items-center gap-2 mb-3">
        <ShieldOff className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Never-block safelist</h2>
        <span className="text-xs text-muted-foreground">
          org-scoped; containment refuses these targets before any dispatch
        </span>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Working"
          />
        )}
      </div>

      <p className="mb-3 text-xs text-muted-foreground max-w-3xl">
        These entries add to a universal baseline that lives in code — public
        resolvers, critical-infrastructure domains and reserved ranges are
        protected for every org and are not listed or removable here. Removing an
        entry below only lifts <em>this</em> org&rsquo;s extra protection.
      </p>

      {entries.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="safelist-empty">
          No org-specific entries — only the universal baseline applies.
        </p>
      ) : (
        <ul className="space-y-1.5" data-testid="safelist-list">
          {entries.map((entry) => (
            <li
              key={entry.id}
              className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card/50 px-3 py-2 text-xs"
              data-testid={`safelist-entry-${entry.id}`}
            >
              <span className="rounded border border-border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {SAFELIST_ENTRY_TYPE_LABELS[entry.entry_type] ??
                  entry.entry_type}
              </span>
              <span className="font-mono">{entry.value}</span>
              <span className="flex-1 min-w-32 text-muted-foreground">
                {entry.reason || <span className="italic">no reason recorded</span>}
              </span>
              {confirmingId === entry.id ? (
                <span className="inline-flex items-center gap-2">
                  <span className="text-severity-medium">Allow containment again?</span>
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={busy}
                    onClick={() => void handleRemove(entry)}
                    data-testid={`safelist-remove-confirm-${entry.id}`}
                  >
                    Remove
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() => setConfirmingId(null)}
                    data-testid={`safelist-remove-cancel-${entry.id}`}
                  >
                    Cancel
                  </Button>
                </span>
              ) : (
                <button
                  onClick={() => setConfirmingId(entry.id)}
                  disabled={busy}
                  aria-label={`Remove ${entry.value}`}
                  className="text-muted-foreground hover:text-severity-medium"
                  data-testid={`safelist-remove-${entry.id}`}
                >
                  <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      <form
        className="mt-3 flex flex-wrap items-start gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void handleAdd();
        }}
      >
        <NativeSelect
          value={entryType}
          onChange={(e) => setEntryType(e.target.value as SafelistEntryType)}
          aria-label="Entry type"
          data-testid="safelist-add-type"
          className="h-9 w-28"
        >
          {/* Rendered from the shared vocabulary rather than hand-listed:
              `principal` was a valid, service-enforced entry kind that this
              dropdown never offered, so cloud IAM principals (#117) could not
              be safelisted from the product at all. */}
          {(
            Object.keys(SAFELIST_ENTRY_TYPE_LABELS) as SafelistEntryType[]
          ).map((kind) => (
            <option key={kind} value={kind}>
              {SAFELIST_ENTRY_TYPE_LABELS[kind]}
            </option>
          ))}
        </NativeSelect>
        <Input
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setFormError(null);
          }}
          placeholder={entryType === "ip" ? "198.51.100.10" : "corp.example.com"}
          aria-label="IP or domain to never block"
          data-testid="safelist-add-value"
          className="h-9 w-56 font-mono"
        />
        <Input
          value={reason}
          onChange={(e) => {
            setReason(e.target.value);
            setFormError(null);
          }}
          placeholder="Why it must never be blocked"
          aria-label="Reason"
          data-testid="safelist-add-reason"
          className="h-9 w-72"
        />
        <Button type="submit" size="sm" disabled={busy} data-testid="safelist-add-button">
          <Plus className="w-4 h-4 mr-1" aria-hidden="true" />
          Add entry
        </Button>
        {formError && (
          <p
            className="w-full text-xs text-severity-medium"
            role="alert"
            data-testid="safelist-add-error"
          >
            {formError}
          </p>
        )}
      </form>
    </section>
  );
}
