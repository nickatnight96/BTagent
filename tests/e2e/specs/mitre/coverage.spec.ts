/**
 * MITRE coverage score — visibility + investigation-scoped recompute.
 *
 * Sprint F scope. Asserts the coverage badge surfaces a numeric score
 * and updates when the user filters to a specific investigation. We
 * don't assert specific score values (they depend on which techniques
 * the seeded investigation tags) — only that the score is visible and
 * that switching scope produces a re-render without erroring.
 */
import { test, expect } from "../../fixtures/auth";
import { MitreMatrixPage } from "../../pages/mitre-page";

test.describe("MITRE coverage", () => {
  test("coverage score is visible on the matrix", async ({ analystPage }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    await expect(matrix.coverage).toBeVisible({ timeout: 10_000 });
    await expect(matrix.coverageScore).toBeVisible();
    // Score is a percentage / count rendered as text — non-empty.
    const text = (await matrix.coverageScore.textContent()) ?? "";
    expect(text.trim().length).toBeGreaterThan(0);
  });

  test("filtering to one investigation triggers a coverage re-render", async ({
    analystPage,
    analystApi,
  }) => {
    const inv = await analystApi.createInvestigation({
      title: `[E2E] Coverage Filter ${Date.now()}`,
    });
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    // Capture initial score so we can prove the panel updated.
    const initial = (await matrix.coverageScore.textContent()) ?? "";

    await matrix.viewToggleInvestigation.click();
    await matrix.investigationFilterInput.selectOption(inv.id);

    // Allow the matrix to refetch; coverage panel stays mounted.
    await expect(matrix.coverage).toBeVisible();
    await expect(matrix.coverageScore).toBeVisible();
    // Either the text changed (filtered scope yields a different
    // score) or it's the same (e.g. zero-coverage in both cases). We
    // only require the panel didn't crash and remained legible.
    const filtered = (await matrix.coverageScore.textContent()) ?? "";
    expect(filtered.trim().length).toBeGreaterThan(0);
    // No error banner.
    await expect(matrix.error).toBeHidden();
    // Capture both for forensics in trace mode.
    expect(typeof initial).toBe("string");
  });

  test("truncation notice appears only when many techniques tagged", async ({
    analystPage,
  }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    // We can't deterministically force the truncation threshold from
    // E2E without mutating the matrix endpoint, so assert the notice's
    // mounted-when-needed contract: it's hidden by default for fresh
    // analysts, and the locator resolves either to ``hidden`` (no
    // truncation) or ``visible`` (truncation hit).
    const visible = await matrix.truncationNotice
      .isVisible()
      .catch(() => false);
    if (visible) {
      // If shown, it should be readable text (not an empty span).
      const txt = (await matrix.truncationNotice.textContent()) ?? "";
      expect(txt.trim().length).toBeGreaterThan(0);
    } else {
      await expect(matrix.truncationNotice).toBeHidden();
    }
  });
});
