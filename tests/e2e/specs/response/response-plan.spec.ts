/**
 * Response Plan slice (EPIC-3 UC-3.2) — generate a containment plan, approve
 * the destructive steps, stage them.
 *
 * Runs against the mock-mode backend (deterministic per-intent catalog), so the
 * plan is stable. The analyst persona holds ``response:plan``. Nothing executes:
 * staging is a proposal-only affordance.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoResponse(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToResponsePlan();
  await page.getByTestId("response-plan").waitFor({ state: "visible", timeout: 10_000 });
}

test.describe("Response Plan", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    await gotoResponse(analystPage);
    await expect(analystPage.getByTestId("response-plan")).toBeVisible();
    await expect(analystPage.getByTestId("response-plan-submit")).toBeEnabled();
  });

  test("sample incident produces a plan with a destructive isolate step", async ({
    analystPage,
  }) => {
    await gotoResponse(analystPage);
    await analystPage.getByRole("button", { name: /use sample incident/i }).click();
    await analystPage.getByTestId("response-plan-submit").click();

    const result = analystPage.getByTestId("response-plan-result");
    await expect(result).toBeVisible({ timeout: 20_000 });
    // Malware / critical / WS-12 → isolate host, destructive, 5m target, rollback.
    await expect(result).toContainText(/isolate host/i);
    await expect(result).toContainText(/WS-12/);
    await expect(result).toContainText(/destructive/i);
    await expect(result).toContainText(/rollback/i);
    await expect(result).toContainText(/5m target/i);
  });

  test("approving destructive steps enables staging", async ({ analystPage }) => {
    await gotoResponse(analystPage);
    await analystPage.getByRole("button", { name: /use sample incident/i }).click();
    await analystPage.getByTestId("response-plan-submit").click();

    const result = analystPage.getByTestId("response-plan-result");
    await expect(result).toBeVisible({ timeout: 20_000 });

    const stage = analystPage.getByTestId("response-plan-stage");
    await expect(stage).toBeDisabled(); // a destructive step is unapproved

    const boxes = result.locator('input[type="checkbox"]');
    const n = await boxes.count();
    expect(n).toBeGreaterThan(0);
    for (let k = 0; k < n; k++) await boxes.nth(k).check();

    await expect(stage).toBeEnabled();
    await stage.click();
    await expect(analystPage.getByTestId("response-plan-staged")).toContainText(/staged/i);
  });
});
