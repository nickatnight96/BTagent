/**
 * Bulk Mitigation slice (EPIC-3 UC-3.3) — paste IOCs, get a per-tool block
 * plan, approve the destructive blocks, stage them.
 *
 * Runs against the mock-mode backend (deterministic allowlist + validation +
 * routing), so the plan is stable. The analyst persona holds ``mitigation:plan``.
 * Nothing executes: staging is a proposal-only affordance.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoMitigation(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToMitigation();
  await page.getByTestId("bulk-mitigation").waitFor({ state: "visible", timeout: 10_000 });
}

test.describe("Bulk Mitigation", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    await gotoMitigation(analystPage);
    await expect(analystPage.getByTestId("bulk-mitigation")).toBeVisible();
    await expect(analystPage.getByTestId("bulk-mitigation-submit")).toBeDisabled(); // no IOCs
  });

  test("sample IOCs produce a plan with blocks, allowlist skips, and previews", async ({
    analystPage,
  }) => {
    await gotoMitigation(analystPage);
    await analystPage.getByRole("button", { name: /use sample iocs/i }).click();
    await expect(analystPage.getByTestId("bulk-mitigation-submit")).toBeEnabled();
    await analystPage.getByTestId("bulk-mitigation-submit").click();

    const result = analystPage.getByTestId("bulk-mitigation-result");
    await expect(result).toBeVisible({ timeout: 20_000 });
    // Public IP/domain/URL/hash → block; 8.8.8.8 + 10.0.0.5 → allowlisted; CVE → unsupported.
    await expect(result).toContainText(/to block/i);
    await expect(result).toContainText(/skip allowlisted/i);
    await expect(result).toContainText(/destructive/i);
    await expect(result).toContainText(/rollback/i);
    // A policy-change preview line is rendered for blocks.
    await expect(result).toContainText(/action=deny/i);
  });

  test("approving every block enables staging", async ({ analystPage }) => {
    await gotoMitigation(analystPage);
    await analystPage.getByRole("button", { name: /use sample iocs/i }).click();
    await analystPage.getByTestId("bulk-mitigation-submit").click();

    const result = analystPage.getByTestId("bulk-mitigation-result");
    await expect(result).toBeVisible({ timeout: 20_000 });

    const stage = analystPage.getByTestId("bulk-mitigation-stage");
    await expect(stage).toBeDisabled(); // blocks unapproved

    await analystPage.getByRole("button", { name: /approve all/i }).click();
    await expect(stage).toBeEnabled();
    await stage.click();
    await expect(analystPage.getByTestId("bulk-mitigation-staged")).toContainText(/staged/i);
  });
});
