import { useEffect, useState } from "react";
import { KeyRound, Loader2, Users } from "lucide-react";
import { toast } from "sonner";
import { listOrgUsers, revokeUserSessions, type OrgUser } from "@/api/users";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { Button } from "@/components/ds/button";

/** Pull a human-readable message out of an ApiError's JSON ``detail`` body. */
function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: string } | null)?.detail;
    if (typeof detail === "string" && detail) return detail;
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
 * Admin session revocation (#142).
 *
 * ``POST /auth/revoke/{user_id}`` has been implemented, tenant-scoped and
 * admin-only since it landed, and had no caller — because nothing in the
 * product listed users, so nothing could name a target. An incident responder
 * holding a report of a stolen laptop had no way to kill that person's
 * sessions from the console; the control existed only over curl.
 *
 * Both the roster and the revoke require ``user:edit``, so for everyone below
 * admin the GET 403s and the panel hides itself — the same self-effacing
 * convention the other Configuration Center panels use.
 *
 * Two things this panel is careful to *say*, because getting them wrong is an
 * incident-response failure rather than a UI annoyance:
 *
 * 1. **Revocation is not a lockout.** It invalidates tokens issued before now;
 *    the user can sign in again immediately with the same credentials. An
 *    admin who thinks they have disabled an account and walks away has not.
 * 2. **For SSO users there is no password to rotate.** Revocation is the only
 *    lever this product has, and the follow-up has to happen at the IdP.
 */
export function SessionRevocationPanel() {
  const [users, setUsers] = useState<OrgUser[] | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  // Revocation returns 204 and leaves no readable state — the epoch lives in
  // Redis, not on the user row — so the "done" marker is local to this view.
  const [revoked, setRevoked] = useState<Set<string>>(new Set());
  const currentUserId = useAuthStore((s) => s.user?.id ?? null);

  useEffect(() => {
    let cancelled = false;
    listOrgUsers()
      .then((rows) => {
        if (!cancelled) setUsers(rows);
      })
      .catch(() => {
        if (!cancelled) setUsers(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (users === null) return null;

  const handleRevoke = async (user: OrgUser) => {
    setBusyId(user.id);
    try {
      await revokeUserSessions(user.id);
      setRevoked((prev) => new Set(prev).add(user.id));
      setConfirmingId(null);
      toast.success(`Signed ${user.username} out of every session`);
    } catch (e) {
      toast.error(errMessage(e, `Could not revoke sessions for ${user.username}`));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <section data-testid="session-revocation-panel">
      <div className="flex items-center gap-2 mb-3">
        <Users className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Users &amp; sessions</h2>
        <span className="text-xs text-muted-foreground">
          org-scoped; revoking invalidates every token issued before now
        </span>
        {busyId && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Working"
          />
        )}
      </div>

      <p className="mb-3 max-w-3xl text-xs text-muted-foreground">
        Revocation is <strong>not</strong> a lockout. It kills the sessions that exist
        right now; the account keeps working and the user can sign in again
        immediately. Pair it with a password reset — or, for SSO accounts, an
        action at the identity provider — if the credential itself is suspect.
      </p>

      {users.length === 0 ? (
        <p className="text-xs text-muted-foreground" data-testid="session-revocation-empty">
          No users in this organisation.
        </p>
      ) : (
        <ul className="space-y-1.5" data-testid="session-revocation-list">
          {users.map((user) => {
            const isSelf = user.id === currentUserId;
            return (
              <li
                key={user.id}
                className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card/50 px-3 py-2 text-xs"
                data-testid={`session-user-${user.id}`}
              >
                <span className="font-medium">{user.username}</span>
                {isSelf && (
                  <span
                    className="rounded border border-border px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                    data-testid={`session-self-${user.id}`}
                  >
                    you
                  </span>
                )}
                <span className="rounded border border-border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                  {user.role}
                </span>
                {user.sso_only && (
                  // Not decoration: it tells the admin that revocation is the
                  // only lever here and the real follow-up is at the IdP.
                  <span
                    className="rounded border border-sky-500/40 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-sky-300"
                    title="No local password — reset must happen at the identity provider"
                    data-testid={`session-sso-${user.id}`}
                  >
                    SSO
                  </span>
                )}
                <span className="flex-1 min-w-40 text-muted-foreground">
                  last login {formatWhen(user.last_login)}
                </span>

                {revoked.has(user.id) ? (
                  <span
                    className="text-emerald-400"
                    data-testid={`session-revoked-${user.id}`}
                  >
                    sessions revoked
                  </span>
                ) : confirmingId === user.id ? (
                  <span className="inline-flex items-center gap-2">
                    <span className="text-severity-medium">
                      {isSelf
                        ? "This signs you out here too. Continue?"
                        : `Sign ${user.username} out everywhere?`}
                    </span>
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={busyId !== null}
                      onClick={() => void handleRevoke(user)}
                      data-testid={`session-revoke-confirm-${user.id}`}
                    >
                      Revoke
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busyId !== null}
                      onClick={() => setConfirmingId(null)}
                      data-testid={`session-revoke-cancel-${user.id}`}
                    >
                      Cancel
                    </Button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirmingId(user.id)}
                    disabled={busyId !== null}
                    className="inline-flex items-center gap-1 text-muted-foreground hover:text-severity-medium"
                    data-testid={`session-revoke-${user.id}`}
                  >
                    <KeyRound className="w-3.5 h-3.5" aria-hidden="true" />
                    Revoke sessions
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
