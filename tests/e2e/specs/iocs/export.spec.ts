/**
 * IOC export — dialog opening, format radios, TLP warning, download.
 *
 * Sprint E. Submission flow uses ``page.waitForEvent("download")`` to
 * confirm a real export blob is produced; we don't crack open the
 * bundle here (that's covered in tlp-egress.spec.ts).
 */
import { test, expect } from "../../fixtures/auth";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";
import { hydrateInvestigationsThenGotoIOCs } from "../../fixtures/navigation";

test.describe("IOC export dialog", () => {
  test("opens via the toolbar button", async ({ analystPage }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.exportButton.click();
    await expect(notebook.exportDialog.root).toBeVisible();
    await expect(notebook.exportDialog.investigationInput).toBeVisible();
  });

  test("investigation selector lists the user's investigations", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { investigation } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Export selector ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.10.${stamp % 240}` }],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(analystPage);
    await notebook.exportButton.click();

    // Selector must include the seeded investigation as an option.
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await expect(notebook.exportDialog.investigationInput).toHaveValue(
      investigation.id,
    );
  });

  test("format radio toggles aria-checked between STIX, CSV, JSON", async ({
    analystPage,
  }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.exportButton.click();

    const stix = notebook.exportDialog.formatRadio("stix_2.1");
    const csv = notebook.exportDialog.formatRadio("csv");
    const json = notebook.exportDialog.formatRadio("json");

    // STIX is the documented default.
    await expect(stix).toHaveAttribute("aria-checked", "true");
    await expect(csv).toHaveAttribute("aria-checked", "false");

    await csv.click();
    await expect(csv).toHaveAttribute("aria-checked", "true");
    await expect(stix).toHaveAttribute("aria-checked", "false");

    await json.click();
    await expect(json).toHaveAttribute("aria-checked", "true");
    await expect(csv).toHaveAttribute("aria-checked", "false");
  });

  test("TLP warning appears when tlp_max >= amber", async ({
    analystPage,
  }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.exportButton.click();

    // No warning at GREEN.
    await notebook.exportDialog.tlpInput.selectOption("green");
    await expect(notebook.exportDialog.tlpWarning).toBeHidden();

    // Warning fires at AMBER.
    await notebook.exportDialog.tlpInput.selectOption("amber");
    await expect(notebook.exportDialog.tlpWarning).toBeVisible();

    // And at RED.
    await notebook.exportDialog.tlpInput.selectOption("red");
    await expect(notebook.exportDialog.tlpWarning).toBeVisible();
  });

  test("submit triggers a file download", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { investigation } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Export download ${stamp}`,
      iocs: [
        { type: "ip", value: `198.18.20.${stamp % 240}` },
        { type: "domain", value: `export-${stamp}.example.invalid` },
      ],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(analystPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("csv").click();

    const downloadPromise = analystPage.waitForEvent("download", {
      timeout: 15_000,
    });
    await notebook.exportDialog.submitButton.click();
    const download = await downloadPromise;
    // Download filename pattern is ``iocs_export_<ts>.<ext>``.
    expect(download.suggestedFilename()).toMatch(/iocs_export_\d+\..+/);
  });
});
