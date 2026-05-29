/**
 * Admin-driven SSO account linking (#169) — admin-only surface.
 *
 * ``sso:link`` / ``sso:unlink`` are admin. The admin persona sees the nav item
 * and the management surface and can load a user's (empty) identity set; a
 * plain analyst never sees the nav item at all (the surface is hidden, not
 * just server-denied). Runs against the mock-mode backend; the sso_identity
 * registry is real (Postgres in CI). No IdP is configured in CI, so this spec
 * deliberately does not exercise a successful link (which needs a configured
 * provider) — that path is covered by the backend unit tests in #172.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

test.describe("SSO Account Linking", () => {
  test("admin sees the linking surface and can load a user", async ({
    adminPage,
  }) => {
    await adminPage.goto("/");
    const sidebar = new Sidebar(adminPage);
    await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });

    // The admin nav item is present.
    await expect(sidebar.ssoIdentitiesLink).toBeVisible();
    await sidebar.goToSsoIdentities();

    await expect(adminPage.getByTestId("sso-identities")).toBeVisible({
      timeout: 10_000,
    });
    await expect(adminPage.getByTestId("sso-identities-link-form")).toBeVisible();

    // Loading an arbitrary user id returns its (empty) identity set — the GET
    // does not require a configured IdP, so this is deterministic.
    await adminPage.getByTestId("sso-identities-user-input").fill("usr_e2e_probe");
    await adminPage.getByTestId("sso-identities-load-button").click();
    await expect(adminPage.getByTestId("sso-identities-table")).toContainText(
      "No linked identities",
      { timeout: 10_000 }
    );
  });

  test("analyst never sees the SSO linking nav item", async ({
    analystPage,
  }) => {
    await analystPage.goto("/");
    const sidebar = new Sidebar(analystPage);
    await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
    // Surface is hidden for non-admins (not merely server-denied).
    await expect(sidebar.ssoIdentitiesLink).toHaveCount(0);
  });
});
