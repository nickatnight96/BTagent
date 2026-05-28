import {
  useState,
  useCallback,
  useEffect,
  type FormEvent,
  type KeyboardEvent,
} from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Eye, EyeOff, Loader2 } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
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
import { ThemeToggle } from "@/components/theme-toggle";
import { ssoEnabled, startSsoLogin } from "@/api/sso";

/**
 * Login screen — first canonical view on the new design system.
 *
 * Reads only semantic tokens (background, card, foreground,
 * muted-foreground, primary, destructive, border) so light + dark
 * themes both render correctly. The ThemeToggle in the corner is the
 * one place a user can switch themes pre-login.
 */
export function LoginPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const {
    login,
    verifyMfa,
    cancelMfa,
    mfaRequired,
    isLoading,
    error,
    clearError,
  } = useAuthStore();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  // MFA (#144): second-factor code entered after a password that gated on MFA.
  const [mfaCode, setMfaCode] = useState("");

  // Clear any stale errors on mount. We deliberately do NOT call the
  // network ``logout()`` here — that would POST to ``/auth/logout``,
  // which revokes the access-token jti server-side. In a multi-tab /
  // multi-context environment (and in parallel test runs that share
  // an .auth storage state across workers) that revocation cascades
  // into spurious "session expired" redirects on the OTHER context's
  // next protected request.
  useEffect(() => {
    clearError();
  }, [clearError]);

  // Shared post-auth navigation: honour ``?redirect=`` (same-origin only).
  const goToNext = useCallback(() => {
    const next = searchParams.get("redirect");
    const target =
      next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
    navigate(target, { replace: true });
  }, [navigate, searchParams]);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      if (!username.trim() || !password.trim()) return;

      // ``login`` returns false when an MFA challenge is required; the store's
      // ``mfaRequired`` flag (read below) drives the second-factor view. Only
      // a fully-established session navigates away.
      const success = await login(username.trim(), password);
      if (success) {
        goToNext();
      }
    },
    [username, password, login, goToNext]
  );

  const handleMfaSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      const code = mfaCode.trim();
      if (!code) return;
      const success = await verifyMfa(code);
      if (success) {
        setMfaCode("");
        goToNext();
      }
    },
    [mfaCode, verifyMfa, goToNext]
  );

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Enter") {
        void handleSubmit(e as unknown as FormEvent);
      }
    },
    [handleSubmit]
  );

  const disabled = isLoading || !username.trim() || !password.trim();

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      {/* Theme switcher — pre-login affordance so people can pick their
       * preferred palette before even authenticating. */}
      <div className="absolute top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      {/* Soft background colour wash */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md" data-testid="login">
        {/* Branding */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10 border border-primary/20 mb-4">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-3xl font-bold text-foreground tracking-tight">
            BTagent
          </h1>
          <p className="text-muted-foreground mt-2 text-sm">
            Defensive Security AI Platform
          </p>
        </div>

        {mfaRequired ? (
          <Card>
            <CardHeader>
              <CardTitle>Two-factor authentication</CardTitle>
              <CardDescription>
                Enter the 6-digit code from your authenticator app, or a
                recovery code.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={handleMfaSubmit}
                className="space-y-4"
                data-testid="mfa-form"
              >
                <div className="space-y-2">
                  <Label htmlFor="mfa-code">Authentication code</Label>
                  <Input
                    id="mfa-code"
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    value={mfaCode}
                    onChange={(e) => {
                      setMfaCode(e.target.value);
                      if (error) clearError();
                    }}
                    autoFocus
                    data-testid="mfa-code-input"
                  />
                </div>

                {error && (
                  <div
                    className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                    role="alert"
                    data-testid="mfa-error"
                  >
                    {error}
                  </div>
                )}

                <Button
                  type="submit"
                  className="w-full"
                  size="lg"
                  disabled={isLoading || !mfaCode.trim()}
                  data-testid="mfa-submit-button"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Verifying…
                    </>
                  ) : (
                    "Verify"
                  )}
                </Button>

                <button
                  type="button"
                  onClick={() => {
                    setMfaCode("");
                    cancelMfa();
                  }}
                  className="w-full text-center text-xs text-muted-foreground hover:text-foreground transition-colors"
                  data-testid="mfa-cancel-button"
                >
                  Back to sign in
                </button>
              </form>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle>Sign in</CardTitle>
              <CardDescription>
                Enter your credentials to access your workspace.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={handleSubmit}
                className="space-y-4"
                data-testid="login-form"
              >
              <div className="space-y-2">
                <Label htmlFor="login-username">Username</Label>
                <Input
                  id="login-username"
                  type="text"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (error) clearError();
                  }}
                  onKeyDown={handleKeyDown}
                  autoComplete="username"
                  autoFocus
                  data-testid="login-username-input"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="login-password">Password</Label>
                <div className="relative">
                  <Input
                    id="login-password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (error) clearError();
                    }}
                    onKeyDown={handleKeyDown}
                    autoComplete="current-password"
                    className="pr-10"
                    data-testid="login-password-input"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    tabIndex={-1}
                    aria-label={
                      showPassword ? "Hide password" : "Show password"
                    }
                    data-testid="login-password-toggle"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              {error && (
                <div
                  className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                  role="alert"
                  data-testid="login-error"
                >
                  {error}
                </div>
              )}

              <Button
                type="submit"
                className="w-full"
                size="lg"
                disabled={disabled}
                data-testid="login-submit-button"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Signing in…
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>

              {/* SSO (#144): full-page redirect to the backend login endpoint,
               * which 302s to the IdP. Only rendered when a provider is
               * configured at build time (VITE_SSO_PROVIDER) so the default
               * deployment / existing E2E suites are unaffected. */}
              {ssoEnabled && (
                <>
                  <div className="relative my-2">
                    <div className="absolute inset-0 flex items-center">
                      <span className="w-full border-t border-border" />
                    </div>
                    <div className="relative flex justify-center text-xs">
                      <span className="bg-card px-2 text-muted-foreground">
                        or
                      </span>
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    size="lg"
                    disabled={isLoading}
                    onClick={() => startSsoLogin()}
                    data-testid="login-sso-button"
                  >
                    Sign in with SSO
                  </Button>
                </>
              )}
            </form>
            </CardContent>
          </Card>
        )}

        <p className="text-center text-xs text-muted-foreground mt-6">
          Authorized personnel only. All access is monitored and logged.
        </p>
      </div>
    </div>
  );
}
