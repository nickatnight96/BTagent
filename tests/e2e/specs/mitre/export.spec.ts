/**
 * MITRE Navigator export — matrix-level + per-technique downloads.
 *
 * Sprint F scope. Drives the export buttons with a stubbed Navigator
 * endpoint so the test is deterministic regardless of seed coverage:
 * the previous version called the live API which returned empty data
 * in CI's small-seed environment, the catch path swallowed the error,
 * and no download ever fired.
 *
 * Pattern: ``page.route`` stubs the ``/api/v1/mitre/navigator-export``
 * response; the SPA wraps the JSON in a Blob, programmatically clicks
 * an ``<a download>``, and Playwright's ``waitForEvent('download')``
 * captures it.
 */
import { test, expect } from "../../fixtures/auth";
import { MitreMatrixPage } from "../../pages/mitre-page";

const PROBE_TECHNIQUE_IDS = ["T1078", "T1059", "T1566", "T1190", "T1486"];

const STUB_NAVIGATOR_LAYER = {
  name: "[E2E] stub Navigator layer",
  domain: "enterprise-attack",
  description: "Stubbed for deterministic E2E export assertion.",
  techniques: [
    { techniqueID: "T1078", color: "#fc3d3d", score: 90, comment: "" },
    { techniqueID: "T1059", color: "#ffaa33", score: 60, comment: "" },
  ],
};

async function firstAvailableTechnique(
  matrix: MitreMatrixPage,
): Promise<string | null> {
  for (const id of PROBE_TECHNIQUE_IDS) {
    if (await matrix.techniqueCell(id).isVisible().catch(() => false)) {
      return id;
    }
  }
  return null;
}

test.describe("MITRE Navigator export", () => {
  test("matrix-level export button triggers a download", async ({
    analystPage,
  }) => {
    // Stub the Navigator export so the test doesn't depend on the
    // (possibly-empty) live coverage in the CI seed.
    await analystPage.route("**/api/v1/mitre/navigator-export*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(STUB_NAVIGATOR_LAYER),
      }),
    );

    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    await expect(matrix.exportButton).toBeVisible();

    const downloadPromise = analystPage.waitForEvent("download", {
      timeout: 15_000,
    });
    await matrix.exportButton.click();
    const download = await downloadPromise;

    const suggested = download.suggestedFilename();
    expect(suggested).toBeTruthy();
    // Navigator export is JSON; filename should reflect that.
    expect(suggested.toLowerCase()).toMatch(/\.json$/);
  });

  test("per-technique export from the detail modal triggers a download", async ({
    analystPage,
  }) => {
    await analystPage.route("**/api/v1/mitre/navigator-export*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(STUB_NAVIGATOR_LAYER),
      }),
    );

    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    const techniqueId = await firstAvailableTechnique(matrix);
    test.skip(!techniqueId, "No probed technique cells rendered in this seed");

    const modal = await matrix.openTechnique(techniqueId!);
    await expect(modal.exportButton).toBeVisible();

    const downloadPromise = analystPage.waitForEvent("download", {
      timeout: 15_000,
    });
    await modal.exportButton.click();
    const download = await downloadPromise;

    const suggested = download.suggestedFilename();
    expect(suggested).toBeTruthy();
    expect(suggested.toLowerCase()).toMatch(/\.json$/);
    // The filename ought to reference the technique id so analysts can
    // tell exports apart at a glance. Tolerate either with or without
    // the leading ``T`` ("t1078" / "T1078").
    const rootId = techniqueId!.split(".")[0] ?? techniqueId!;
    expect(suggested.toLowerCase()).toContain(rootId.toLowerCase());
  });
});
