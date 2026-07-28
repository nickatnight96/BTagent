import api from "./client";

/**
 * A user of the caller's organisation, as `GET /auth/users` returns them.
 *
 * The roster deliberately carries no credential material — see the endpoint's
 * docstring. `sso_only` is the field that changes what an admin should *do*:
 * for an SSO-provisioned account there is no local password to rotate, so
 * revoking sessions is the only lever this product has.
 */
export interface OrgUser {
  id: string;
  username: string;
  email: string;
  role: string;
  created_at: string;
  last_login: string | null;
  sso_only: boolean;
}

/**
 * The caller's org roster. Admin-only (`user:edit`) — the same gate as the
 * revocation it feeds, so anyone who can read this can act on it.
 */
export async function listOrgUsers(): Promise<OrgUser[]> {
  return api.get<OrgUser[]>("/v1/auth/users");
}

/**
 * Revoke every outstanding session for a user (#142).
 *
 * Sets a per-user revocation epoch: every access and refresh token issued
 * before now is rejected. It is not a lockout — the user can log in again
 * immediately and the new tokens carry a later `iat`. Use it on credential
 * compromise or offboarding, paired with a password reset or IdP action
 * depending on whether the account has a local credential at all.
 */
export async function revokeUserSessions(userId: string): Promise<void> {
  await api.post<void>(`/v1/auth/revoke/${encodeURIComponent(userId)}`, {});
}
