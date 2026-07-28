import { useEffect, useState } from "react";
import { KeyRound, Loader2, RefreshCw, UserPlus, Users } from "lucide-react";
import { toast } from "sonner";
import {
  ASSIGNABLE_ROLES,
  MIN_PASSWORD_LENGTH,
  listOrgUsers,
  provisionUser,
  revokeUserSessions,
  type AssignableRole,
  type OrgUser,
} from "@/api/users";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { NativeSelect } from "@/components/ds/native-select";

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

const PASSWORD_ALPHABET =
  "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_=+.?";

/**
 * Generate an initial password.
 *
 * `crypto.getRandomValues`, never `Math.random` — this string is a real
 * credential from the moment it is submitted. Rejection sampling rather than
 * `% alphabet.length`, which would bias toward the first few characters.
 *
 * The alphabet omits look-alikes (l/1/I, O/0) because this value gets read
 * aloud or retyped when it is handed over.
 */
function generatePassword(length = 20): string {
  const max = 256 - (256 % PASSWORD_ALPHABET.length);
  const out: string[] = [];
  const buf = new Uint8Array(1);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    const byte = buf[0] ?? 0;
    if (byte < max) out.push(PASSWORD_ALPHABET.charAt(byte % PASSWORD_ALPHABET.length));
  }
  return out.join("");
}

function prettyRole(role: string): string {
  return role.replace(/_/g, " ");
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

  // Provisioning form (#142 companion: POST /auth/register had no UI either,
  // so accounts could only be created over curl).
  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newRole, setNewRole] = useState<AssignableRole>("analyst");
  const [newPassword, setNewPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

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

  const handleProvision = async () => {
    const username = newUsername.trim();
    const email = newEmail.trim();
    if (!username || !email) {
      setFormError("Username and email are both required.");
      return;
    }
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      // A local pre-check only, to save a round trip. The server owns the
      // rule and its 422 detail is what gets shown if the two ever disagree.
      setFormError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    setFormError(null);
    setCreating(true);
    try {
      const created = await provisionUser({
        username,
        email,
        password: newPassword,
        role: newRole,
      });
      // Optimistically append rather than refetching: the roster is the same
      // org and the new row's shape is fully determined. `sso_only` is false
      // because provisioning always sets a local password.
      setUsers((prev) => [
        ...(prev ?? []),
        {
          id: created.id,
          username: created.username,
          email,
          role: created.role,
          created_at: new Date().toISOString(),
          last_login: null,
          sso_only: false,
        },
      ]);
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      toast.success(`Provisioned ${created.username} as ${prettyRole(created.role)}`);
    } catch (e) {
      setFormError(errMessage(e, "Could not provision the account"));
    } finally {
      setCreating(false);
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

      <form
        className="mt-4 border-t border-border pt-3"
        onSubmit={(e) => {
          e.preventDefault();
          void handleProvision();
        }}
        data-testid="provision-user-form"
      >
        <div className="mb-2 flex items-center gap-2">
          <UserPlus className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
          <h3 className="text-xs font-medium">Provision an account</h3>
          <span className="text-xs text-muted-foreground">
            joins this organisation; the role can only be changed by re-provisioning
          </span>
        </div>

        <div className="flex flex-wrap items-start gap-2">
          <Input
            value={newUsername}
            onChange={(e) => {
              setNewUsername(e.target.value);
              setFormError(null);
            }}
            placeholder="username"
            aria-label="Username"
            data-testid="provision-username"
            className="h-9 w-44"
          />
          <Input
            type="email"
            value={newEmail}
            onChange={(e) => {
              setNewEmail(e.target.value);
              setFormError(null);
            }}
            placeholder="name@corp.example"
            aria-label="Email"
            data-testid="provision-email"
            className="h-9 w-56"
          />
          <NativeSelect
            value={newRole}
            onChange={(e) => setNewRole(e.target.value as AssignableRole)}
            aria-label="Role"
            data-testid="provision-role"
            className="h-9 w-44"
          >
            {ASSIGNABLE_ROLES.map((r) => (
              <option key={r} value={r}>
                {prettyRole(r)}
              </option>
            ))}
          </NativeSelect>
          <Input
            // Deliberately not type="password": the admin is setting a
            // credential for someone else and has to read it back to hand it
            // over. Masking it would only invite a screenshot of the
            // clipboard instead.
            value={newPassword}
            onChange={(e) => {
              setNewPassword(e.target.value);
              setFormError(null);
            }}
            placeholder={`initial password (${MIN_PASSWORD_LENGTH}+ chars)`}
            aria-label="Initial password"
            data-testid="provision-password"
            className="h-9 w-64 font-mono"
          />
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => {
              setNewPassword(generatePassword());
              setFormError(null);
            }}
            data-testid="provision-generate"
          >
            <RefreshCw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            Generate
          </Button>
          <Button type="submit" size="sm" disabled={creating} data-testid="provision-submit">
            {creating ? (
              <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <UserPlus className="mr-1 h-4 w-4" aria-hidden="true" />
            )}
            Create account
          </Button>
        </div>

        <p className="mt-2 max-w-3xl text-xs text-muted-foreground">
          The password is shown rather than masked so it can be handed over, and
          it is <strong>not</strong> rotated on first sign-in — the account keeps
          it until the user changes it themselves.
        </p>

        {formError && (
          <p
            className="mt-2 text-xs text-severity-medium"
            role="alert"
            data-testid="provision-error"
          >
            {formError}
          </p>
        )}
      </form>
    </section>
  );
}
