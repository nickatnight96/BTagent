import { useState, useCallback } from "react";
import { Loader2, KeyRound, Link2, Trash2, Search } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  listSSOIdentities,
  linkSSOIdentity,
  unlinkSSOIdentity,
  ssoProvider,
  type SSOIdentity,
} from "@/api/sso";
import { ApiError } from "@/api/client";

/** Pull a human-readable message out of an ApiError's JSON ``detail`` body. */
function errMessage(e: unknown, fallback: string): string {
  if (e instanceof ApiError) {
    const detail = (e.body as { detail?: string } | null)?.detail;
    if (detail) return detail;
    if (e.status === 404) return "Not found";
    if (e.status === 409) return "Conflict";
  }
  return e instanceof Error ? e.message : fallback;
}

export function SSOIdentitiesPage() {
  // The user whose identities we're managing. ``loadedUserId`` is the id the
  // current table reflects (set on a successful load), so the link form knows
  // which user a new identity attaches to.
  const [userIdInput, setUserIdInput] = useState("");
  const [loadedUserId, setLoadedUserId] = useState<string | null>(null);
  const [identities, setIdentities] = useState<SSOIdentity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // link-form state
  const [provider, setProvider] = useState(ssoProvider ?? "");
  const [subject, setSubject] = useState("");
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async (userId: string) => {
    setLoading(true);
    setError(null);
    try {
      const rows = await listSSOIdentities(userId);
      setIdentities(rows);
      setLoadedUserId(userId);
    } catch (e) {
      setError(errMessage(e, "Failed to load identities"));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleLoad = useCallback(() => {
    const id = userIdInput.trim();
    if (!id) return;
    void load(id);
  }, [userIdInput, load]);

  const handleLink = useCallback(async () => {
    if (!loadedUserId) return;
    setSubmitting(true);
    setError(null);
    try {
      await linkSSOIdentity({
        user_id: loadedUserId,
        provider: provider.trim(),
        subject: subject.trim(),
        email: email.trim() || null,
      });
      setSubject("");
      setEmail("");
      await load(loadedUserId);
    } catch (e) {
      setError(errMessage(e, "Failed to link identity"));
    } finally {
      setSubmitting(false);
    }
  }, [loadedUserId, provider, subject, email, load]);

  const handleUnlink = useCallback(
    async (id: string) => {
      setError(null);
      try {
        await unlinkSSOIdentity(id);
        if (loadedUserId) await load(loadedUserId);
      } catch (e) {
        setError(errMessage(e, "Failed to unlink identity"));
      }
    },
    [loadedUserId, load]
  );

  const canLink =
    !!loadedUserId && provider.trim() !== "" && subject.trim() !== "";

  return (
    <>
      <Header title="SSO Account Linking" />
      <div
        className="flex-1 overflow-y-auto p-6 space-y-6"
        data-testid="sso-identities"
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-primary" />
              Bind accounts to an identity provider
            </CardTitle>
            <CardDescription>
              SSO login never <em>silently</em> binds an identity provider to an
              existing password account — that would let a misconfigured IdP
              asserting a victim's email seize their account. This admin surface
              is the explicit, audited override: link a known{" "}
              <code>(provider, subject)</code> to a chosen user. Once linked, the
              user can sign in via SSO; their password login is unaffected.
              Admin only (#169).
            </CardDescription>
          </CardHeader>
          {error && (
            <CardContent>
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                role="alert"
                data-testid="sso-identities-error"
              >
                {error}
              </div>
            </CardContent>
          )}
        </Card>

        {/* Find user */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Search className="w-4 h-4 text-primary" />
              Find a user
            </CardTitle>
            <CardDescription>
              Enter the user's id (e.g. <code>usr_…</code>) to view and manage
              their linked identities.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
              <div className="space-y-1.5 flex-1">
                <Label htmlFor="sso-user-id">User id</Label>
                <Input
                  id="sso-user-id"
                  value={userIdInput}
                  onChange={(e) => setUserIdInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLoad()}
                  placeholder="usr_01J…"
                  data-testid="sso-identities-user-input"
                />
              </div>
              <Button
                onClick={handleLoad}
                disabled={loading || userIdInput.trim() === ""}
                data-testid="sso-identities-load-button"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Loading…
                  </>
                ) : (
                  "Load identities"
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Link form */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Link2 className="w-4 h-4 text-primary" />
              Link an identity
            </CardTitle>
            <CardDescription>
              {loadedUserId ? (
                <>
                  Attaching to user{" "}
                  <span className="font-mono">{loadedUserId}</span>.
                </>
              ) : (
                "Load a user above to enable linking."
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4" data-testid="sso-identities-link-form">
            <div className="grid sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="sso-provider">Provider</Label>
                <Input
                  id="sso-provider"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  placeholder="okta"
                  data-testid="sso-identities-provider-input"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sso-subject">Subject (IdP sub)</Label>
                <Input
                  id="sso-subject"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="00u1a2b3c4…"
                  data-testid="sso-identities-subject-input"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sso-email">Email (optional)</Label>
                <Input
                  id="sso-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@corp.example"
                  data-testid="sso-identities-email-input"
                />
              </div>
            </div>
            <Button
              onClick={handleLink}
              disabled={!canLink || submitting}
              data-testid="sso-identities-link-button"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Linking…
                </>
              ) : (
                "Link identity"
              )}
            </Button>
          </CardContent>
        </Card>

        {/* List */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Linked identities{" "}
              {loading && <Loader2 className="inline w-4 h-4 animate-spin" />}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-md border border-border">
              <table
                className="w-full text-xs"
                data-testid="sso-identities-table"
              >
                <thead className="bg-card">
                  <tr className="text-left text-muted-foreground">
                    <th className="px-2 py-2 font-medium">Provider</th>
                    <th className="px-2 py-2 font-medium">Subject</th>
                    <th className="px-2 py-2 font-medium">Email</th>
                    <th className="px-2 py-2 font-medium">Linked</th>
                    <th className="px-2 py-2 font-medium text-right" />
                  </tr>
                </thead>
                <tbody>
                  {identities.map((i) => (
                    <tr key={i.id} className="border-t border-border/40">
                      <td className="px-2 py-1.5">
                        <Badge variant="low">{i.provider}</Badge>
                      </td>
                      <td className="px-2 py-1.5 font-mono max-w-xs truncate">
                        {i.subject}
                      </td>
                      <td className="px-2 py-1.5 text-muted-foreground">
                        {i.email ?? "—"}
                      </td>
                      <td className="px-2 py-1.5 text-muted-foreground">
                        {new Date(i.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-2 py-1.5 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleUnlink(i.id)}
                          data-testid={`sso-identities-unlink-${i.id}`}
                          aria-label={`Unlink ${i.provider} identity`}
                        >
                          <Trash2 className="w-4 h-4 text-destructive" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                  {identities.length === 0 && !loading && (
                    <tr>
                      <td
                        colSpan={5}
                        className="px-2 py-8 text-center text-muted-foreground"
                      >
                        {loadedUserId
                          ? "No linked identities for this user."
                          : "Load a user to see their linked identities."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
