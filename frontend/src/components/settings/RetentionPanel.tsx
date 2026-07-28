import { useCallback, useEffect, useState } from "react";
import { Archive, Loader2, ShieldCheck, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ds/button";
import {
  getRetentionStats,
  runRetentionCleanup,
  type RetentionRunResult,
  type RetentionStats,
} from "@/api/configSchema";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

/**
 * Data retention posture + manual cleanup (#418).
 *
 * `GET /config/retention` and `POST /config/retention/run` shipped with no
 * consumer, so how long incident data is kept — and whether the audit ledger
 * still satisfies its compliance window — could only be asked with curl. The
 * reachability ratchet (#473) named both; this closes them.
 *
 * The run is treated as a **destructive action, not a refresh**, because it
 * is: it permanently deletes stale events and archives closed investigations.
 * So the panel shows what is at stake *before* offering the button, the button
 * needs an explicit confirmation, and the result reports the counts actually
 * affected rather than a bare "done".
 *
 * Read is `config:view` (analyst+) — knowing the retention posture is not
 * privileged. Running is `config:edit` (admin), enforced server-side.
 */
export function RetentionPanel() {
  const role = useAuthStore((s) => s.user?.role);
  const canRun = role === UserRole.ADMIN;

  const [stats, setStats] = useState<RetentionStats | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RetentionRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStats(await getRetentionStats());
    } catch {
      // Self-effacing, like the other Configuration Center panels: retention
      // is one section of that page, not a dependency of it.
      setStats(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (stats === null) return null;

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    try {
      setResult(await runRetentionCleanup());
      setConfirming(false);
      // Re-read: the counts the panel shows are now stale by construction.
      await load();
    } catch {
      setError("Retention cleanup failed — nothing was deleted.");
    } finally {
      setRunning(false);
    }
  };

  const auditCompliant = result?.audit_verification.compliant;

  return (
    <section data-testid="retention-panel">
      <div className="mb-3 flex items-center gap-2">
        <Archive className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Data retention</h2>
        <span className="text-xs text-muted-foreground">
          what is held, and what is past its window
        </span>
        {running && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Running cleanup"
          />
        )}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div
          className="rounded-md border border-border bg-card/50 p-3 text-xs"
          data-testid="retention-events"
        >
          <p className="font-medium">Events</p>
          <p className="mt-1 text-muted-foreground">
            {stats.events.total.toLocaleString()} held ·{" "}
            <span className={stats.events.stale > 0 ? "text-amber-400" : ""}>
              {stats.events.stale.toLocaleString()} past {stats.events.retention_days}d
            </span>
          </p>
        </div>

        <div
          className="rounded-md border border-border bg-card/50 p-3 text-xs"
          data-testid="retention-investigations"
        >
          <p className="font-medium">Investigations</p>
          <p className="mt-1 text-muted-foreground">
            {stats.investigations.total.toLocaleString()} held ·{" "}
            <span className={stats.investigations.archivable > 0 ? "text-amber-400" : ""}>
              {stats.investigations.archivable.toLocaleString()} archivable
            </span>
          </p>
        </div>

        <div
          className="rounded-md border border-border bg-card/50 p-3 text-xs"
          data-testid="retention-audit"
        >
          <p className="font-medium">Audit ledger</p>
          <p className="mt-1 text-muted-foreground">
            {stats.audit_logs.total.toLocaleString()} entries ·{" "}
            {stats.audit_logs.retention_years}y window
          </p>
          {/* The ledger is never pruned by this run — worth stating on the
           * card, so nobody assumes a cleanup touches the evidence chain. */}
          <p className="mt-1 text-emerald-400">
            {stats.audit_logs.policy === "never_delete"
              ? "never deleted by cleanup"
              : stats.audit_logs.policy}
          </p>
        </div>
      </div>

      {canRun && (
        <div className="mt-3">
          {confirming ? (
            <div
              className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs"
              role="alert"
              data-testid="retention-confirm"
            >
              <p className="font-semibold text-destructive">
                This permanently deletes {stats.events.stale.toLocaleString()} event
                {stats.events.stale === 1 ? "" : "s"} and archives{" "}
                {stats.investigations.archivable.toLocaleString()} investigation
                {stats.investigations.archivable === 1 ? "" : "s"}. It cannot be undone.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={running}
                  onClick={() => void handleRun()}
                  data-testid="retention-run-confirm"
                >
                  Run cleanup
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={running}
                  onClick={() => setConfirming(false)}
                  data-testid="retention-run-cancel"
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setConfirming(true);
                setResult(null);
              }}
              data-testid="retention-run"
            >
              Run cleanup now
            </Button>
          )}
        </div>
      )}

      {error && (
        <p className="mt-2 text-xs text-severity-medium" role="alert" data-testid="retention-error">
          {error}
        </p>
      )}

      {result && (
        <div
          className="mt-3 rounded-md border border-border bg-card/50 p-3 text-xs"
          role="status"
          data-testid="retention-result"
        >
          <p>
            Deleted{" "}
            <span className="font-medium">{result.events.deleted_count.toLocaleString()}</span>{" "}
            event{result.events.deleted_count === 1 ? "" : "s"} and archived{" "}
            <span className="font-medium">
              {result.investigations.archived_count.toLocaleString()}
            </span>{" "}
            investigation{result.investigations.archived_count === 1 ? "" : "s"}.
          </p>
          <p
            className={`mt-1 flex items-center gap-1.5 ${
              auditCompliant ? "text-emerald-400" : "text-destructive"
            }`}
            data-testid="retention-audit-compliance"
          >
            {auditCompliant ? (
              <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
            ) : (
              <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            {auditCompliant
              ? `Audit ledger meets its ${result.audit_verification.retention_years}-year window.`
              : "Audit ledger is NOT within its compliance window."}
          </p>
          {/* A failed compliance check is the finding, not a footnote — the
           * reasons are what an auditor will ask about. */}
          {!auditCompliant && (result.audit_verification.issues?.length ?? 0) > 0 && (
            <ul className="mt-1 list-disc pl-4 text-destructive/90" data-testid="retention-audit-issues">
              {result.audit_verification.issues?.map((i) => (
                <li key={i}>{i}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
