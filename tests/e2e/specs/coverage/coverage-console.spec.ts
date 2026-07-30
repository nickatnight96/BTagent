/**
 * Coverage Console E2E spec (#501 / #98 Bet 1).
 *
 * The console is a pure composition surface over four existing sources
 * (#118 validation freshness, #112 rule health, MITRE mapping, #113
 * proposals/telemetry gaps), so this spec pins the composition rendering and
 * navigation rather than the underlying data pipelines (each has its own
 * suite):
 *  - the page, summary tiles, heatmap, and all three panels render;
 *  - hunt:view is the floor — a plain analyst gets the full read surface;
 *  - the sidebar nav entry routes to /coverage;
 *  - the stale-days filter round-trips through a reload;
 *  - selecting a heatmap technique opens the deep-link action row.
 *
 * Data posture: the CI stack seeds the MITRE matrix but not validation runs,
 * so heatmap content depends on the environment. Assertions branch on the
 * empty state where the payload legitimately varies — both branches are real
 * renders, never a skip.
 */

import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

async function gotoConsole(page: Page) {
  await page.goto("/coverage");
  await page.getByTestId("coverage-console").waitFor({ state: "visible", timeout: 15_000 });
  // Loading skeleton resolves into either the summary or the error alert;
  // the error alert failing the test is the point.
  await page.getByTestId("coverage-summary").waitFor({ state: "visible", timeout: 15_000 });
}

test.describe("Coverage Console", () => {
  test("renders summary, heatmap, and all three panels", async ({ seniorPage }) => {
    await gotoConsole(seniorPage);

    await expect(seniorPage.getByTestId("coverage-console-error")).toHaveCount(0);
    await expect(seniorPage.getByTestId("coverage-summary")).toBeVisible();
    // MITRE mapping + proposal context line and verdict counts render even
    // when every count is zero.
    await expect(seniorPage.getByTestId("coverage-context-mapped")).toBeVisible();
    await expect(seniorPage.getByTestId("coverage-context-proposals")).toBeVisible();
    await expect(seniorPage.getByTestId("coverage-verdicts")).toBeVisible();

    // Heatmap: populated matrix or its explicit empty state — never neither.
    const heatmap = seniorPage.getByTestId("coverage-heatmap");
    const empty = seniorPage.getByTestId("coverage-heatmap-empty");
    expect((await heatmap.count()) + (await empty.count())).toBeGreaterThan(0);

    await expect(seniorPage.getByTestId("broken-rules-panel")).toBeVisible();
    await expect(seniorPage.getByTestId("telemetry-gaps-panel")).toBeVisible();
    await expect(seniorPage.getByTestId("next-best-actions-panel")).toBeVisible();
  });

  test("hunt:view is the floor — a plain analyst gets the full read surface", async ({
    analystPage,
  }) => {
    await gotoConsole(analystPage);
    await expect(analystPage.getByTestId("coverage-summary")).toBeVisible();
    await expect(analystPage.getByTestId("broken-rules-panel")).toBeVisible();
    await expect(analystPage.getByTestId("next-best-actions-panel")).toBeVisible();
  });

  test("sidebar nav entry routes to /coverage", async ({ seniorPage }) => {
    await seniorPage.goto("/");
    await seniorPage.getByTestId("nav-coverage-link").click();
    await seniorPage
      .getByTestId("coverage-console")
      .waitFor({ state: "visible", timeout: 10_000 });
    expect(seniorPage.url()).toContain("/coverage");
  });

  test("stale-days filter round-trips", async ({ seniorPage }) => {
    await gotoConsole(seniorPage);

    const staleInput = seniorPage.getByTestId("coverage-stale-days");
    await staleInput.fill("30");
    await seniorPage.getByTestId("coverage-apply").click();

    // The refetch resolves back into a rendered summary with the tightened
    // window still applied in the control.
    await seniorPage.getByTestId("coverage-summary").waitFor({ state: "visible", timeout: 15_000 });
    await expect(staleInput).toHaveValue("30");
    await expect(seniorPage.getByTestId("coverage-console-error")).toHaveCount(0);
  });

  test("selecting a heatmap technique opens the deep-link action row", async ({
    seniorPage,
  }) => {
    await gotoConsole(seniorPage);

    const cells = seniorPage.locator('[data-testid^="coverage-cell-"]');
    if ((await cells.count()) === 0) {
      // Legitimately empty matrix in this environment — the empty state must
      // say so explicitly (and there is no cell to select).
      await expect(seniorPage.getByTestId("coverage-heatmap-empty")).toBeVisible();
      return;
    }

    await cells.first().click();
    const selected = seniorPage.getByTestId("coverage-selected");
    await expect(selected).toBeVisible();
    await expect(seniorPage.getByTestId("coverage-selected-status")).toBeVisible();
    // The three deep links into the #118 / #113 / MITRE surfaces.
    await expect(seniorPage.getByTestId("coverage-selected-validate")).toBeVisible();
    await expect(seniorPage.getByTestId("coverage-selected-propose")).toBeVisible();
    await expect(seniorPage.getByTestId("coverage-selected-matrix")).toBeVisible();
  });
});
