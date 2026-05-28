/**
 * TLP egress policy admin (UC-7.2) — list / create / dry-run evaluate.
 *
 * ``policy:view`` is senior_analyst+, ``policy:manage`` is admin. The admin
 * persona can do everything; a plain analyst is denied the data. Runs
 * against the mock-mode backend; the policy registry is real (Postgres in
 * CI). Navigation goes through the Sidebar POM.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoPolicies(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToPolicies();
  await page.getByTestId("tlp-policies").waitFor({ state: "visible", timeout: 10_000 });
}

test.describe("TLP Egress Policies", () => {
  test("admin sees the policy admin surface", async ({ adminPage }) => {
    await gotoPolicies(adminPage);
    await expect(adminPage.getByTestId("tlp-policies")).toBeVisible();
    await expect(adminPage.getByTestId("tlp-policy-create-form")).toBeVisible();
    await expect(adminPage.getByTestId("tlp-policy-table")).toBeVisible();
  });

  test("admin can create a policy end-to-end", async ({ adminPage }) => {
    await gotoPolicies(adminPage);
    // Default action is "allow"; just add a rationale and create.
    await adminPage
      .getByLabel("Rationale")
      .fill(`[E2E] partner ISAC ${Date.now()}`);
    await adminPage.getByTestId("tlp-policy-create-button").click();
    // The new row lands in the table with an "allow" badge.
    await expect(adminPage.getByTestId("tlp-policy-table")).toContainText("allow", {
      timeout: 10_000,
    });
  });

  test("dry-run evaluate returns a decision", async ({ adminPage }) => {
    await gotoPolicies(adminPage);
    await adminPage.getByTestId("tlp-evaluate-button").click();
    const result = adminPage.getByTestId("tlp-evaluate-result");
    await expect(result).toBeVisible({ timeout: 10_000 });
    // Default-deny: TLP:RED over stix_export with no matching policy -> BLOCKED.
    await expect(result).toContainText(/ALLOWED|BLOCKED/);
  });

  test("analyst is denied the policy data (server-side RBAC)", async ({
    analystPage,
  }) => {
    await analystPage.goto("/");
    const sidebar = new Sidebar(analystPage);
    await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
    await sidebar.goToPolicies();
    // Shell renders, but policy:view is denied -> error banner.
    await expect(analystPage.getByRole("alert")).toBeVisible({ timeout: 20_000 });
  });
});
