/**
 * Workflows list slice (Phase 4 — Slice A).
 *
 * The list renders for any analyst (``workflow:view``); creating a workflow
 * is a senior-analyst capability (``workflow:create``), so the create flow
 * uses the ``seniorPage`` persona. Runs against the live backend.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoWorkflows(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToWorkflows();
  await page.getByTestId("workflow-list").waitFor({ state: "visible", timeout: 10_000 });
}

test.describe("Workflows list", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    await gotoWorkflows(analystPage);
    await expect(analystPage.getByTestId("workflow-list")).toBeVisible();
    await expect(analystPage.getByTestId("workflow-create-open")).toBeVisible();
  });

  test("senior analyst can create a workflow and see it listed", async ({ seniorPage }) => {
    await gotoWorkflows(seniorPage);

    const unique = `E2E WF ${Date.now()}`;
    await seniorPage.getByTestId("workflow-create-open").click();
    await seniorPage.getByTestId("workflow-name-input").fill(unique);
    await seniorPage.getByTestId("workflow-create-submit").click();

    // The dialog closes and the new workflow appears in the list.
    const card = seniorPage.getByTestId("workflow-card").filter({ hasText: unique });
    await expect(card).toBeVisible({ timeout: 15_000 });
  });
});
