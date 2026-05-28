import { useCallback, useEffect, useState } from "react";
import { ShieldCheck, Loader2, Copy } from "lucide-react";
import { mfaApi, type MfaEnrollResult, type MfaStatus } from "@/api/mfa";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";

/**
 * Minimal MFA enrollment / management panel (#144, Phase 1a).
 *
 * Scoped and dependency-light: there is no QR library in the bundle, so we
 * render the ``otpauth://`` provisioning URI + the base32 secret as text for
 * manual entry, plus the one-time recovery codes (shown once). A later phase
 * can swap in a QR renderer without touching the backend contract.
 */
export function MfaSettingsPage() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [enrollment, setEnrollment] = useState<MfaEnrollResult | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await mfaApi.status());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load MFA status");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const startEnroll = useCallback(async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setEnrollment(await mfaApi.enroll());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Enrollment failed");
    } finally {
      setBusy(false);
    }
  }, []);

  const confirm = useCallback(async () => {
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await mfaApi.confirm(code.trim());
      setEnrollment(null);
      setCode("");
      setNotice("Two-factor authentication is now enabled.");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }, [code, refresh]);

  const disable = useCallback(async () => {
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await mfaApi.disable(code.trim());
      setCode("");
      setNotice("Two-factor authentication has been disabled.");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }, [code, refresh]);

  const copy = (value: string) => {
    void navigator.clipboard?.writeText(value);
  };

  return (
    <div className="flex-1 space-y-6 p-6 max-w-2xl">
      <div className="flex items-center gap-3">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold text-foreground">
          Two-factor authentication
        </h1>
      </div>

      {notice && (
        <div
          className="rounded-md border border-primary/30 bg-primary/10 p-3 text-sm text-foreground"
          role="status"
          data-testid="mfa-notice"
        >
          {notice}
        </div>
      )}
      {error && (
        <div
          className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
          role="alert"
          data-testid="mfa-settings-error"
        >
          {error}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>
            {status?.enabled ? "MFA is enabled" : "MFA is not enabled"}
          </CardTitle>
          <CardDescription>
            {status?.enabled
              ? "You will be prompted for a code from your authenticator app each time you sign in."
              : "Protect your account with a time-based one-time password (TOTP)."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Not enabled, not mid-enrollment: offer to start. */}
          {!status?.enabled && !enrollment && (
            <Button
              onClick={startEnroll}
              disabled={busy}
              data-testid="mfa-enroll-button"
            >
              {busy ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : null}
              Set up authenticator app
            </Button>
          )}

          {/* Mid-enrollment: show secret + URI + recovery codes, then confirm. */}
          {enrollment && (
            <div className="space-y-4" data-testid="mfa-enroll-panel">
              <div className="space-y-1">
                <Label>Provisioning URI (add to your authenticator)</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 break-all rounded bg-muted p-2 text-xs">
                    {enrollment.provisioning_uri}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    onClick={() => copy(enrollment.provisioning_uri)}
                    aria-label="Copy provisioning URI"
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-1">
                <Label>Manual entry secret</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 break-all rounded bg-muted p-2 text-sm tracking-wider">
                    {enrollment.secret}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    onClick={() => copy(enrollment.secret)}
                    aria-label="Copy secret"
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-1">
                <Label>Recovery codes (save these now — shown once)</Label>
                <div className="grid grid-cols-2 gap-2 rounded border border-border p-3">
                  {enrollment.recovery_codes.map((c) => (
                    <code key={c} className="text-sm">
                      {c}
                    </code>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="mfa-confirm-code">
                  Enter a code to confirm
                </Label>
                <Input
                  id="mfa-confirm-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  data-testid="mfa-confirm-input"
                />
              </div>
              <Button
                onClick={confirm}
                disabled={busy || !code.trim()}
                data-testid="mfa-confirm-button"
              >
                {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Confirm and enable
              </Button>
            </div>
          )}

          {/* Enabled: allow disabling with a current code. */}
          {status?.enabled && !enrollment && (
            <div className="space-y-2">
              <Label htmlFor="mfa-disable-code">
                Enter a current code to disable
              </Label>
              <Input
                id="mfa-disable-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                data-testid="mfa-disable-input"
              />
              <Button
                variant="destructive"
                onClick={disable}
                disabled={busy || !code.trim()}
                data-testid="mfa-disable-button"
              >
                {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Disable MFA
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
