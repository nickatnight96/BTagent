/**
 * Configuration Center (#418) — inventory render + the two edit flows.
 *
 * Covers the acceptance criteria end-to-end against the live stack: the
 * runtime-surface cards and deploy-time table render with secrets redacted,
 * an admin can add/toggle/remove a feature flag, and an admin can set and
 * clear a per-category autonomy override. A plain analyst sees the same
 * inventory read-only — no selects, no flag controls — which is the UI half
 * of the server-side ``config:edit`` gate.
 *
 * Every write here is idempotent-by-construction: the flag key is
 * timestamped, and the autonomy flow resets to defaults at the end, so the
 * spec can re-run against a dirty database (CI runs single-worker, but the
 * org config store persists across specs in the same run).
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoConfig(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToConfig();
  await page.getByTestId("config-center").waitFor({ state: "visible", timeout: 15_000 });
  // The env table only renders once GET /config/schema resolves.
  await page
    .getByTestId("config-center-env-table")
    .waitFor({ state: "visible", timeout: 15_000 });
}

test.describe("Configuration Center", () => {
  test("renders the inventory with secrets redacted", async ({ adminPage }) => {
    await gotoConfig(adminPage);

    // Runtime surfaces: the org-profile card is always present, with a scope
    // badge and a deep link into its existing editor.
    await expect(adminPage.getByTestId("config-surface-org_profile")).toBeVisible();
    await expect(adminPage.getByTestId("config-surface-org_profile-scope")).toHaveText(
      "org",
    );
    await expect(
      adminPage.getByTestId("config-surface-org_profile-link"),
    ).toHaveAttribute("href", "/settings");

    // Deploy-time knobs: the JWT secret is present as a row but redacted —
    // the value never reaches the browser.
    await expect(adminPage.getByTestId("config-env-jwt_secret")).toBeVisible();
    await expect(
      adminPage.getByTestId("config-env-jwt_secret-redacted"),
    ).toBeVisible();
    await expect(adminPage.getByTestId("config-env-env")).toContainText("test");

    // The name filter narrows the table.
    await adminPage.getByTestId("config-center-env-filter").fill("jwt");
    await expect(adminPage.getByTestId("config-env-env")).toBeHidden();
    await expect(adminPage.getByTestId("config-env-jwt_secret")).toBeVisible();
    await adminPage.getByTestId("config-center-env-filter").fill("zzz-no-match");
    await expect(adminPage.getByTestId("config-center-env-empty")).toBeVisible();
  });

  test("admin can add, toggle and remove a feature flag", async ({ adminPage }) => {
    await gotoConfig(adminPage);
    const key = `e2e_flag_${Date.now()}`;

    await adminPage.getByTestId("feature-flags-add-input").fill(key);
    await adminPage.getByTestId("feature-flags-add-button").click();

    const row = adminPage.getByTestId(`feature-flag-${key}`);
    await expect(row).toBeVisible({ timeout: 10_000 });
    // New flags land off.
    const toggle = adminPage.getByTestId(`feature-flag-toggle-${key}`);
    await expect(toggle).not.toBeChecked();

    await toggle.click();
    await expect(toggle).toBeChecked({ timeout: 10_000 });

    // Remove it again so repeat runs don't accumulate flags.
    await adminPage.getByTestId(`feature-flag-remove-${key}`).click();
    await expect(row).toBeHidden({ timeout: 10_000 });
  });

  test("admin can set and clear an autonomy override", async ({ adminPage }) => {
    await gotoConfig(adminPage);

    const select = adminPage.getByTestId("autonomy-select-siem_query");
    await expect(select).toBeVisible();
    await select.selectOption("L1");

    // The saved override round-trips: the badge appears and the select holds
    // the new level (state comes back from the server's response).
    await expect(adminPage.getByTestId("autonomy-overridden-siem_query")).toBeVisible({
      timeout: 10_000,
    });
    await expect(select).toHaveValue("L1");

    // Containment is never configurable — locked chip, no select.
    await expect(
      adminPage.getByTestId("autonomy-hitl-lock-host_isolation"),
    ).toBeVisible();
    await expect(
      adminPage.getByTestId("autonomy-select-host_isolation"),
    ).toHaveCount(0);

    // Reset returns the org to pure defaults (and leaves the DB clean).
    await adminPage.getByTestId("autonomy-reset-button").click();
    await expect(
      adminPage.getByTestId("autonomy-overridden-siem_query"),
    ).toHaveCount(0, { timeout: 10_000 });
    await expect(select).toHaveValue("");
  });

  test("analyst sees the inventory read-only", async ({ analystPage }) => {
    await gotoConfig(analystPage);

    // Same inventory (config:view is analyst+)...
    await expect(analystPage.getByTestId("config-surface-org_profile")).toBeVisible();
    await expect(analystPage.getByTestId("autonomy-category-siem_query")).toBeVisible();

    // ...but no edit affordances anywhere: no autonomy selects, no reset,
    // no flag add-input.
    await expect(analystPage.getByTestId("autonomy-select-siem_query")).toHaveCount(0);
    await expect(analystPage.getByTestId("autonomy-reset-button")).toHaveCount(0);
    await expect(analystPage.getByTestId("feature-flags-add-input")).toHaveCount(0);
  });
});
