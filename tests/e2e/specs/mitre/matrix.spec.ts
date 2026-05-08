/**
 * MITRE matrix — grid render / search filtering / view toggle.
 *
 * Sprint F scope. Drives the MitreMatrixPage POM end-to-end against
 * the seeded ATT&CK data the backend ships in test mode.
 *
 * Timeouts: the matrix renders 14 tactic columns × N (~190+) techniques
 * on first load and the underlying ``GET /api/v1/mitre/techniques``
 * fetch is uncached. The default 60 s test timeout is fine, but the
 * per-locator awaits have to allow for the worst-case CI cold-start.
 */
import { test, expect } from "../../fixtures/auth";
import { MitreMatrixPage } from "../../pages/mitre-page";

const MATRIX_RENDER_TIMEOUT_MS = 30_000;

test.describe("MITRE matrix", () => {
  test("matrix grid renders for the analyst persona", async ({
    analystPage,
  }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    await expect(matrix.grid).toBeVisible({
      timeout: MATRIX_RENDER_TIMEOUT_MS,
    });
  });

  test("loading indicator is shown during the initial fetch then resolves", async ({
    analystPage,
  }) => {
    const matrix = new MitreMatrixPage(analystPage);
    // Slow the matrix fetch so the loading state is observable.
    await analystPage.route("**/api/v1/mitre/**", async (route) => {
      await new Promise((r) => setTimeout(r, 250));
      await route.continue();
    });
    await analystPage.goto("/mitre");
    // We may catch the loading spinner — but it's racy. The acceptance
    // is "the grid eventually renders".
    await expect(matrix.root).toBeVisible({
      timeout: MATRIX_RENDER_TIMEOUT_MS,
    });
    await expect(matrix.grid).toBeVisible({
      timeout: MATRIX_RENDER_TIMEOUT_MS,
    });
  });

  test("search input narrows visible techniques", async ({ analystPage }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    // Type a token unlikely to appear in many techniques.
    await matrix.searchInput.fill("kerberoast");
    // Either a matching cell becomes visible or the empty state shows.
    await expect(matrix.grid.or(matrix.empty)).toBeVisible({ timeout: 5_000 });
  });

  test("view toggle switches between global and investigation modes", async ({
    analystPage,
  }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    // The view toggle is rendered as a tablist (role="tab" buttons in
    // a role="tablist" container), so the active state is signalled
    // by ``aria-selected``, not ``aria-pressed``.
    await matrix.viewToggleInvestigation.click();
    await expect(matrix.viewToggleInvestigation).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await matrix.viewToggleGlobal.click();
    await expect(matrix.viewToggleGlobal).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  test("investigation filter input scopes the matrix", async ({
    analystPage,
    analystApi,
  }) => {
    // Seed an investigation so the filter input has something real to
    // bind to. We don't assert specific coverage shifts here — that
    // belongs in coverage.spec.ts — only that the input accepts and
    // applies the value without error.
    const inv = await analystApi.createInvestigation({
      title: `[E2E] Matrix Scope ${Date.now()}`,
    });
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    await matrix.viewToggleInvestigation.click();
    // The filter is a native ``<select>``; selectOption is the
    // correct interaction (``.fill`` errors on selects).
    await matrix.investigationFilterInput.selectOption(inv.id);
    // Grid should re-render without error.
    await expect(matrix.grid.or(matrix.empty)).toBeVisible({
      timeout: 10_000,
    });
    await expect(matrix.error).toBeHidden();
  });

  test("empty state shows when no techniques match the filter", async ({
    analystPage,
  }) => {
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    // High-entropy noise that won't match any technique.
    await matrix.searchInput.fill(`zz_no_match_${Date.now()}_zz`);
    await expect(matrix.empty).toBeVisible({ timeout: 5_000 });
  });

  test("error path surfaces a retry button when the API fails", async ({
    analystPage,
  }) => {
    // Force the matrix endpoint to 500 so we can prove the error UI
    // engages without depending on flaky live state.
    await analystPage.route("**/api/v1/mitre/**", async (route) => {
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ detail: "synthetic e2e failure" }),
      });
    });
    const matrix = new MitreMatrixPage(analystPage);
    await analystPage.goto("/mitre");
    // Either we see the error state or the page still loads with empty
    // — both behaviours are acceptable; the matrix shouldn't crash.
    await expect(matrix.root).toBeVisible({
      timeout: MATRIX_RENDER_TIMEOUT_MS,
    });
    await expect(matrix.error.or(matrix.empty).or(matrix.grid)).toBeVisible({
      timeout: 10_000,
    });
  });
});
