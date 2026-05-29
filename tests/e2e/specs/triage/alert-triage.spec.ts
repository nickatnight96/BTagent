/**
 * Alert Triage slice (EPIC-3 UC-3.1) — submit an alert, get a reviewed case.
 *
 * Runs against the mock-mode backend (deterministic keyword classifier), so
 * the verdict is stable. The analyst persona holds ``triage:run``.
 */
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

async function gotoTriage(page: import("@playwright/test").Page) {
  await page.goto("/");
  const sidebar = new Sidebar(page);
  await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
  await sidebar.goToTriage();
  await page.getByTestId("alert-triage").waitFor({ state: "visible", timeout: 10_000 });
}

test.describe("Alert Triage", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    await gotoTriage(analystPage);
    await expect(analystPage.getByTestId("alert-triage")).toBeVisible();
    await expect(analystPage.getByTestId("alert-triage-submit")).toBeDisabled(); // empty title
  });

  test("triaging the sample alert renders a reviewed case", async ({ analystPage }) => {
    await gotoTriage(analystPage);
    await analystPage.getByRole("button", { name: /use sample alert/i }).click();
    await expect(analystPage.getByTestId("alert-triage-submit")).toBeEnabled();
    await analystPage.getByTestId("alert-triage-submit").click();

    const result = analystPage.getByTestId("alert-triage-result");
    await expect(result).toBeVisible({ timeout: 20_000 });
    // Sample is Cobalt Strike beaconing → C2, escalated, with next steps.
    await expect(result).toContainText(/c2 beaconing/i);
    await expect(result).toContainText(/escalate/i);
    await expect(result).toContainText(/confidence/i);
    await expect(result).toContainText(/next steps/i);
  });

  test("typing a malware alert classifies + escalates", async ({ analystPage }) => {
    await gotoTriage(analystPage);
    await analystPage.getByTestId("alert-triage-title").fill("Ransomware payload quarantined");
    await analystPage.getByTestId("alert-triage-submit").click();
    const result = analystPage.getByTestId("alert-triage-result");
    await expect(result).toBeVisible({ timeout: 20_000 });
    await expect(result).toContainText(/malware detected/i);
    await expect(result).toContainText(/critical/i);
  });
});
