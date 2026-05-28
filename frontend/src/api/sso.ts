/**
 * Generic OIDC SSO (#144, Phase 1b).
 *
 * SSO login is a *full-page* redirect, not an XHR: the browser must navigate
 * to the backend ``/auth/sso/{provider}/login`` endpoint, which 302s to the
 * IdP. After the user authenticates at the IdP, the backend callback sets the
 * normal httpOnly auth cookies and 302s back to the SPA — so the existing
 * cookie-based ``/auth/me`` hydration (see ``authStore.checkAuth``) picks the
 * session up with no extra client wiring.
 *
 * Provider visibility is build-time only: ``VITE_SSO_PROVIDER`` names the
 * configured IdP key (e.g. "okta"). When unset (the default), no SSO button is
 * shown and nothing about the login flow changes — keeping existing
 * UAT/E2E/login suites unaffected. The button merely kicks off a redirect; if
 * the backend has no matching provider configured the route 404s, which is the
 * documented behaviour.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

/**
 * The configured SSO provider key (build-time), or ``null`` when SSO is not
 * enabled for this deployment.
 */
export const ssoProvider: string | null =
  import.meta.env.VITE_SSO_PROVIDER?.trim() || null;

/** Whether an SSO sign-in affordance should be shown. */
export const ssoEnabled = ssoProvider !== null;

/**
 * Begin an OIDC SSO login by navigating the browser to the backend login
 * endpoint (which redirects to the IdP). Defaults to the configured provider.
 */
export function startSsoLogin(provider: string | null = ssoProvider): void {
  if (!provider) return;
  window.location.assign(
    `${BASE_URL}/v1/auth/sso/${encodeURIComponent(provider)}/login`
  );
}
