/**
 * Visual-regression snapshots for the highest-traffic surfaces.
 *
 * Snapshots are platform-sensitive — Playwright records them per
 * (browser, OS) tuple. The committed baselines were captured on a
 * local chromium-linux runner; GitHub Actions ``ubuntu-latest`` has
 * different font-rendering subpixel behaviour and the
 * ``maxDiffPixelRatio: 0.2`` tolerance isn't enough to absorb the
 * delta.
 *
 * Currently ``describe.skip``'d so the gate doesn't false-flag
 * every CI run. To re-engage the gate (after #64 closure):
 *
 *   1. Trigger the ``Regenerate Visual Baselines`` workflow from
 *      the Actions tab (``workflow_dispatch``). It re-runs these
 *      specs with ``--update-snapshots`` against ubuntu-latest.
 *   2. Download the ``visual-baselines-chromium-linux`` artifact
 *      (30-day retention) and replace
 *      ``tests/e2e/specs/visual/snapshots.spec.ts-snapshots/``
 *      with its contents.
 *   3. Drop the ``test.describe.skip`` below (revert to plain
 *      ``test.describe``).
 *   4. Open a PR; the regular ``e2e`` job will diff against the
 *      newly committed baselines.
 *
 * See ``.github/workflows/regen-visual-baselines.yml``.
 */
import { test, expect } from "../../fixtures/auth";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

const MASK_DYNAMIC = [
  // Mask UI that changes per run / per second so the diff is stable.
  '[data-testid="header-user-name"]',
  '[data-testid="cost-badge-value"]',
  '[data-testid="event-stream-count"]',
];

test.describe.skip("Visual snapshots", () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test("login page — empty form", async ({ page }) => {
    await page.goto("/login");
    await page.getByTestId("login-form").waitFor();
    await expect(page).toHaveScreenshot("login-empty.png", {
      fullPage: true,
      maxDiffPixelRatio: 0.2,
    });
  });

  test("login page — error state", async ({ page }) => {
    await page.goto("/login");
    await page.getByTestId("login-username-input").fill("admin");
    await page.getByTestId("login-password-input").fill("wrong-password");
    await page.getByTestId("login-submit-button").click();
    await page.getByTestId("login-error").waitFor();
    await expect(page).toHaveScreenshot("login-error.png", {
      fullPage: true,
      maxDiffPixelRatio: 0.2,
    });
  });

  test("PunchList — empty", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("investigation-list").waitFor();
    await expect(analystPage).toHaveScreenshot("punchlist-empty.png", {
      fullPage: true,
      maxDiffPixelRatio: 0.2,
      mask: MASK_DYNAMIC.map((s) => analystPage.locator(s)),
    });
  });

  test("PunchList — with cards", async ({ analystPage, analystApi }) => {
    await seedInvestigationWithIOCs(analystApi, {
      title: "[E2E-VIS] Card 1",
    });
    await seedInvestigationWithIOCs(analystApi, {
      title: "[E2E-VIS] Card 2",
    });
    await analystPage.goto("/");
    await analystPage.getByTestId("investigation-list-grid").waitFor();
    await expect(analystPage).toHaveScreenshot("punchlist-with-cards.png", {
      fullPage: true,
      maxDiffPixelRatio: 0.2,
      mask: MASK_DYNAMIC.map((s) => analystPage.locator(s)),
    });
  });

  test("New investigation modal", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("investigation-list-new-button").click();
    await analystPage.getByTestId("new-investigation-dialog").waitFor();
    // Snapshot just the dialog, not the whole page.
    const dialog = analystPage.getByTestId("new-investigation-dialog");
    await expect(dialog).toHaveScreenshot("new-investigation-modal.png", {
      maxDiffPixelRatio: 0.2,
    });
  });

  test("MITRE matrix — overview", async ({ analystPage }) => {
    await analystPage.goto("/mitre");
    await analystPage.getByTestId("mitre-matrix").waitFor();
    // Wait for the grid; it loads asynchronously.
    await analystPage.getByTestId("mitre-matrix-grid").waitFor();
    await expect(analystPage).toHaveScreenshot("mitre-matrix.png", {
      fullPage: false,
      maxDiffPixelRatio: 0.2,
      mask: MASK_DYNAMIC.map((s) => analystPage.locator(s)),
    });
  });

  test("Sidebar — expanded", async ({ analystPage }) => {
    await analystPage.goto("/");
    const sidebar = analystPage.getByTestId("sidebar");
    await sidebar.waitFor();
    await expect(sidebar).toHaveScreenshot("sidebar-expanded.png", {
      maxDiffPixelRatio: 0.2,
    });
  });

  test("Sidebar — collapsed", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("sidebar-collapse-toggle").click();
    const sidebar = analystPage.getByTestId("sidebar");
    await expect(sidebar).toHaveAttribute("data-sidebar-open", "false");
    await expect(sidebar).toHaveScreenshot("sidebar-collapsed.png", {
      maxDiffPixelRatio: 0.2,
    });
  });
});
