/**
 * Admin session revocation (#142).
 *
 * `POST /auth/revoke/{user_id}` shipped tenant-scoped and admin-only and then
 * sat there uncalled, because no endpoint in the product listed users — there
 * was no way to name a target. This panel is the whole vertical: the new
 * roster, and the revoke it feeds.
 *
 * The cases that carry weight are about not letting the UI lie about what
 * revocation *does*: it is not a lockout, and for an SSO account it is the
 * only lever the product has. Plus the destructive-action hygiene — two-step
 * confirm, and an explicit warning when the target is the admin themselves.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const listOrgUsers = vi.fn();
const revokeUserSessions = vi.fn();

vi.mock("@/api/users", () => ({
  listOrgUsers: (...a: unknown[]) => listOrgUsers(...a),
  revokeUserSessions: (...a: unknown[]) => revokeUserSessions(...a),
}));

const toastSuccess = vi.fn();
const toastError = vi.fn();
vi.mock("sonner", () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}));

import { SessionRevocationPanel } from "@/components/settings/SessionRevocationPanel";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

const ADMIN = {
  id: "usr_admin",
  username: "casey",
  email: "casey@corp.test",
  role: "admin",
  created_at: "2026-01-01T00:00:00Z",
  last_login: "2026-07-27T09:00:00Z",
  sso_only: false,
};

const SSO_ANALYST = {
  id: "usr_sso",
  username: "rin",
  email: "rin@corp.test",
  role: "analyst",
  created_at: "2026-02-01T00:00:00Z",
  last_login: null,
  sso_only: true,
};

describe("SessionRevocationPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listOrgUsers.mockResolvedValue([ADMIN, SSO_ANALYST]);
    revokeUserSessions.mockResolvedValue(undefined);
    useAuthStore.setState({
      user: { id: ADMIN.id, username: ADMIN.username, role: UserRole.ADMIN },
    });
  });

  it("hides itself entirely when the roster fetch is refused", async () => {
    // Both roster and revoke need user:edit, so a 403 here means this admin
    // console has nothing to offer — same self-effacing convention as the
    // other Configuration Center panels.
    listOrgUsers.mockRejectedValue(new Error("forbidden"));
    const { container } = render(<SessionRevocationPanel />);
    await waitFor(() => expect(listOrgUsers).toHaveBeenCalled());
    expect(screen.queryByTestId("session-revocation-panel")).toBeNull();
    expect(container.textContent).toBe("");
  });

  it("says plainly that revoking is not a lockout", async () => {
    // An admin who believes they have disabled an account and walks away has
    // not. This sentence is the difference between a contained incident and
    // an uncontained one.
    render(<SessionRevocationPanel />);
    const panel = await screen.findByTestId("session-revocation-panel");
    expect(panel.textContent).toContain("not");
    expect(panel.textContent).toContain("sign in again");
  });

  it("marks SSO accounts, where revocation is the only available lever", async () => {
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    expect(screen.getByTestId(`session-sso-${SSO_ANALYST.id}`)).toBeTruthy();
    // The password-backed account must NOT carry the badge, or it says nothing.
    expect(screen.queryByTestId(`session-sso-${ADMIN.id}`)).toBeNull();
  });

  it("renders never-logged-in rather than a bogus date", async () => {
    render(<SessionRevocationPanel />);
    const row = await screen.findByTestId(`session-user-${SSO_ANALYST.id}`);
    expect(row.textContent).toContain("never");
  });

  it("requires a confirmation before revoking", async () => {
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    fireEvent.click(screen.getByTestId(`session-revoke-${SSO_ANALYST.id}`));
    // Still nothing sent — the first click only arms it.
    expect(revokeUserSessions).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId(`session-revoke-confirm-${SSO_ANALYST.id}`));
    await waitFor(() => expect(revokeUserSessions).toHaveBeenCalledWith(SSO_ANALYST.id));
  });

  it("lets the confirmation be backed out of", async () => {
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    fireEvent.click(screen.getByTestId(`session-revoke-${SSO_ANALYST.id}`));
    fireEvent.click(screen.getByTestId(`session-revoke-cancel-${SSO_ANALYST.id}`));
    expect(screen.getByTestId(`session-revoke-${SSO_ANALYST.id}`)).toBeTruthy();
    expect(revokeUserSessions).not.toHaveBeenCalled();
  });

  it("warns when the target is the admin's own account", async () => {
    // Revoking yourself is legitimate — a stolen session on another device —
    // but it signs you out of this console too, and that must not be a
    // surprise.
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    expect(screen.getByTestId(`session-self-${ADMIN.id}`)).toBeTruthy();

    fireEvent.click(screen.getByTestId(`session-revoke-${ADMIN.id}`));
    const row = screen.getByTestId(`session-user-${ADMIN.id}`);
    expect(row.textContent).toContain("signs you out here too");
  });

  it("marks the row revoked once the server accepts it", async () => {
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    fireEvent.click(screen.getByTestId(`session-revoke-${SSO_ANALYST.id}`));
    fireEvent.click(screen.getByTestId(`session-revoke-confirm-${SSO_ANALYST.id}`));

    expect(await screen.findByTestId(`session-revoked-${SSO_ANALYST.id}`)).toBeTruthy();
    expect(toastSuccess).toHaveBeenCalled();
  });

  it("does not mark the row revoked when the server refuses", async () => {
    // A green "sessions revoked" over a failed call would tell an incident
    // responder the threat is contained when it isn't.
    revokeUserSessions.mockRejectedValue(new Error("boom"));
    render(<SessionRevocationPanel />);
    await screen.findByTestId("session-revocation-list");
    fireEvent.click(screen.getByTestId(`session-revoke-${SSO_ANALYST.id}`));
    fireEvent.click(screen.getByTestId(`session-revoke-confirm-${SSO_ANALYST.id}`));

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(screen.queryByTestId(`session-revoked-${SSO_ANALYST.id}`)).toBeNull();
  });

  it("says so when the org has no other users", async () => {
    listOrgUsers.mockResolvedValue([]);
    render(<SessionRevocationPanel />);
    expect(await screen.findByTestId("session-revocation-empty")).toBeTruthy();
  });
});
