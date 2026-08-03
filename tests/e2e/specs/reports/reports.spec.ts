/**
 * Reports page E2E.
 *
 * `/reports` had zero browser coverage — no spec, no page object, no nav
 * reference anywhere under tests/e2e.
 *
 * **Generation is deliberately not asserted here, because it does not work.**
 * Writing this spec surfaced that `POST /reports/generate` cannot succeed for
 * any case: the route scopes `investigation_id` against the real DB, then
 * delegates to a generator that resolves investigations from a hardcoded
 * `_MOCK_INVESTIGATIONS` dict containing only `inv_mock_001`. A real case
 * passes scoping and 400s in the generator; `inv_mock_001` 404s at scoping.
 * Meanwhile the page's case picker is populated from real investigations, so
 * every id it offers is one generation will reject.
 *
 * A test asserting the current behaviour would enshrine that as intended, and
 * a test asserting success would fail — so this file covers the surface that
 * does work and the defect is tracked separately. The generation flow gets its
 * coverage with the fix.
 *
 * `report:generate` and `report:export` are analyst-level, so the analyst
 * persona is the right one here — no privileged action is involved.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

const PAGE_TIMEOUT = 10_000;

async function openPage(page: Page): Promise<void> {
  await page.goto("/reports");
  await page.getByTestId("reports-page").waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
}

/** Seed a case to report on, so completeness is measured against known input. */
async function seedInvestigation(page: Page, title: string): Promise<string> {
  const resp = await page.request.post("/api/v1/investigations", {
    data: { title, description: "Seeded by reports.spec", severity: "high", tlp_level: "green" },
  });
  expect(
    resp.ok(),
    `seedInvestigation failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

test.describe("Reports page", () => {
  test("page structure renders — case input, template, generate", async ({ analystPage }) => {
    await openPage(analystPage);

    await expect(analystPage.getByRole("heading", { name: "Reports", level: 1 })).toBeVisible();
    await expect(analystPage.getByTestId("reports-investigation-input")).toBeVisible();
    await expect(analystPage.getByTestId("reports-template-select")).toBeVisible();
    await expect(analystPage.getByTestId("reports-generate")).toBeVisible();
  });

  test("sidebar nav link reaches the page", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("nav-reports-link").click();
    await analystPage
      .getByTestId("reports-page")
      .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
    expect(analystPage.url()).toContain("/reports");
  });

  test("generate stays disabled until a case is named", async ({ analystPage }) => {
    await openPage(analystPage);

    // Nothing to report on yet.
    await expect(analystPage.getByTestId("reports-generate")).toBeDisabled();

    const invId = await seedInvestigation(analystPage, `Reports enable ${Date.now()}`);
    await analystPage.getByTestId("reports-investigation-input").fill(invId);
    await expect(analystPage.getByTestId("reports-generate")).toBeEnabled();
  });
});
