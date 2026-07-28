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

/** Roles an admin can assign when provisioning an account. */
export const ASSIGNABLE_ROLES = [
  "analyst",
  "senior_analyst",
  "incident_commander",
  "admin",
] as const;
export type AssignableRole = (typeof ASSIGNABLE_ROLES)[number];

export interface ProvisionUserRequest {
  username: string;
  email: string;
  password: string;
  role: AssignableRole;
}

export interface ProvisionedUser {
  id: string;
  username: string;
  role: string;
}

/**
 * Minimum password length the server enforces.
 *
 * Mirrored here only so the form can disable its own submit button before a
 * round trip. The server owns the rule (`password_length_error`) and its 422
 * detail is what gets shown — this constant is a convenience, never the
 * authority.
 */
export const MIN_PASSWORD_LENGTH = 12;

/**
 * Provision a new account in the caller's org. Admin-only (`user:create`).
 *
 * Despite the endpoint being named `register`, this is not self-registration —
 * it has always required an authenticated admin, and the new user inherits the
 * creating admin's `org_id` rather than taking one from the request body.
 */
export async function provisionUser(body: ProvisionUserRequest): Promise<ProvisionedUser> {
  return api.post<ProvisionedUser>("/v1/auth/register", body);
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
