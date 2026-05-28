/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly DEV: boolean;
  readonly PROD: boolean;
  readonly MODE: string;
  readonly BASE_URL: string;
  readonly VITE_API_URL?: string;
  readonly VITE_WS_URL?: string;
  readonly VITE_API_BASE_URL?: string;
  // Generic OIDC SSO (#144): names the configured IdP provider key (e.g.
  // "okta"). Unset → no SSO sign-in button is shown.
  readonly VITE_SSO_PROVIDER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
