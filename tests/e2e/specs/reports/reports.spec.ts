/**
 * Reports page E2E.
 *
 * `/reports` had zero browser coverage — no spec, no page object, no nav
 * reference anywhere under tests/e2e.
 *
 * Writing the first version of this spec surfaced #554: `POST /reports/generate`
 * could not succeed for *any* case, because the route scoped `investigation_id`
 * against the real DB and then handed the id to a generator that resolved
 * investigations from a hardcoded fixture dict. Generation was left unasserted
 * rather than written against broken behaviour; with the fix in place, the
 * generate and completeness tests land here.
 *
 * The completeness assertions are the ones that matter. The page exists to
 * answer "is this report finishable?", and it answers with a percentage and a
 * gap list derived from the case's own fields — so a sparse case must report
 * gaps. A completeness block scoring 100% on an empty investigation would be
 * measuring the template rather than the case, which is worse than absent: an
 * analyst would sign off on nothing.
 *
 * `report:generate` and `report:export` are analyst-level, so the analyst
 * persona is the right one here — no privileged action is involved.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

const PAGE_TIMEOUT = 10_000;
const GENERATE_TIMEOUT = 30_000;

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

  test("generating against a real case renders completeness and sections (#554)", async ({
    analystPage,
  }) => {
    const runTag = `rep-${Date.now()}`;
    const invId = await seedInvestigation(analystPage, `Reportable case ${runTag}`);

    await openPage(analystPage);
    await analystPage.getByTestId("reports-investigation-input").fill(invId);
    // The hint proves the id resolved to a real case rather than being typed
    // into the void — the input accepts free text on purpose.
    await expect(analystPage.getByTestId("reports-investigation-hint")).toContainText(runTag, {
      timeout: PAGE_TIMEOUT,
    });

    await analystPage.getByTestId("reports-generate").click();

    await expect(analystPage.getByTestId("reports-completeness")).toBeVisible({
      timeout: GENERATE_TIMEOUT,
    });
    await expect(analystPage.getByTestId("reports-completeness-pct")).toContainText("%");
    await expect(analystPage.getByTestId("reports-sections")).toBeVisible();
    await expect(analystPage.getByTestId("reports-export-pdf")).toBeVisible();
    // The report is about the seeded case, not a fixture — the regression #554
    // was precisely that the id and the rendered content could disagree.
    await expect(analystPage.getByTestId("reports-sections")).toContainText(runTag);
  });

  test("a freshly-seeded case reports gaps rather than a clean bill", async ({
    analystPage,
  }) => {
    const invId = await seedInvestigation(analystPage, `Sparse case ${Date.now()}`);

    await openPage(analystPage);
    await analystPage.getByTestId("reports-investigation-input").fill(invId);
    await analystPage.getByTestId("reports-generate").click();

    await expect(analystPage.getByTestId("reports-completeness")).toBeVisible({
      timeout: GENERATE_TIMEOUT,
    });
    await expect(analystPage.getByTestId("reports-gaps")).toBeVisible();
  });
});
