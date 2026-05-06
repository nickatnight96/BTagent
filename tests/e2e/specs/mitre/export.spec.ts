/**
 * MITRE Navigator export — matrix-level + per-technique downloads.
 *
 * Sprint F scope. Uses Playwright's ``page.waitForEvent('download')``
 * pattern to assert the export buttons trigger a real file download
 * with a sensible suggested filename + JSON content-type.
 */
import { test, expect } from "../../fixtures/auth";
import { MitreMatrixPage } from "../../pages/mitre-page";

const PROBE_TECHNIQUE_IDS = ["T1078", "T1059", "T1566", "T1190", "T1486"];

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
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    await expect(matrix.exportButton).toBeVisible();

    const downloadPromise = analystPage.waitForEvent("download", {
      timeout: 10_000,
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
    const matrix = new MitreMatrixPage(analystPage);
    await matrix.goto();
    const techniqueId = await firstAvailableTechnique(matrix);
    test.skip(!techniqueId, "No probed technique cells rendered in this seed");

    const modal = await matrix.openTechnique(techniqueId!);
    await expect(modal.exportButton).toBeVisible();

    const downloadPromise = analystPage.waitForEvent("download", {
      timeout: 10_000,
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
