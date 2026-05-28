/**
 * Correlation Workbench slice (UC-1.2) — enter an entity, fan out across
 * sources, render one normalized timeline + suggested pivots.
 *
 * Mock-mode backend → deterministic timeline. Read-only (L1), so the
 * analyst persona is sufficient.
 */
import { test, expect } from "../../fixtures/auth";
import { CorrelationPage } from "../../pages/slice-pages";

test.describe("Correlation Workbench", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    const corr = new CorrelationPage(analystPage);
    await corr.goto();
    await expect(corr.root).toBeVisible();
    await expect(corr.header.title).toHaveText("Correlation Workbench");
    await expect(corr.correlateButton).toBeDisabled(); // empty entity
  });

  test("sample entity prefills the input", async ({ analystPage }) => {
    const corr = new CorrelationPage(analystPage);
    await corr.goto();
    await corr.sampleButton.click();
    await expect(corr.input).toHaveValue("10.1.42.17");
    await expect(corr.correlateButton).toBeEnabled();
  });

  test("correlating an entity renders a unified timeline", async ({
    analystPage,
  }) => {
    const corr = new CorrelationPage(analystPage);
    await corr.goto();
    await corr.sampleButton.click();
    await corr.correlateButton.click();

    await expect(corr.result).toBeVisible({ timeout: 20_000 });
    await expect(corr.result).toContainText("Unified timeline");
    await expect(corr.result).toContainText("Suggested pivots");
    await expect(corr.error).toHaveCount(0);
  });
});
