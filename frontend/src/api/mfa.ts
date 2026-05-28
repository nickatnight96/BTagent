/**
 * MFA enrollment API (#144).
 *
 * These calls are made from an authed session (cookies attached automatically
 * via `credentials: "include"`). The login-time `/auth/mfa/verify` call lives
 * in the auth store, not here, because it runs pre-session.
 */

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export interface MfaStatus {
  enrolled: boolean;
  enabled: boolean;
}

export interface MfaEnrollResult {
  provisioning_uri: string;
  secret: string;
  recovery_codes: string[];
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE_URL}/v1/auth/mfa/${path}`, {
    method: "POST",
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(err.detail ?? `MFA request failed (${res.status})`);
  }
  // 204 responses have no body.
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const mfaApi = {
  async status(): Promise<MfaStatus> {
    const res = await fetch(`${BASE_URL}/v1/auth/mfa/status`, {
      credentials: "include",
    });
    if (!res.ok) throw new Error(`Failed to load MFA status (${res.status})`);
    return (await res.json()) as MfaStatus;
  },
  enroll(): Promise<MfaEnrollResult> {
    return postJson<MfaEnrollResult>("enroll");
  },
  confirm(code: string): Promise<void> {
    return postJson<void>("confirm", { code });
  },
  disable(code: string): Promise<void> {
    return postJson<void>("disable", { code });
  },
};
