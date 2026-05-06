/**
 * IOC import — modal toggling, format tabs, preview, error, submit.
 *
 * Sprint E. The IOCImportModal POM exposes locators for the format
 * tabs, paste textarea, preview table, error banner, and submit /
 * cancel buttons. Submission goes through the real backend; success
 * is asserted via ``analystApi.listIOCs(...)`` to keep the contract
 * end-to-end (modal → API → DB).
 */
import { test, expect } from "../../fixtures/auth";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test.describe("IOC import modal", () => {
  test("opens via the toolbar button", async ({ analystPage }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();
    await expect(notebook.importModal.root).toBeVisible();
    await expect(notebook.importModal.pasteInput).toBeVisible();
  });

  test("CSV format tab is selected by default; switching to STIX flips aria-selected", async ({
    analystPage,
  }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();

    await expect(notebook.importModal.formatTabCsv).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(notebook.importModal.formatTabStix).toHaveAttribute(
      "aria-selected",
      "false",
    );

    await notebook.importModal.formatTabStix.click();
    await expect(notebook.importModal.formatTabStix).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await expect(notebook.importModal.formatTabCsv).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  test("pasting valid CSV shows a preview table with parsed rows", async ({
    analystPage,
  }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();

    const csv = [
      "type,value,source,confidence,tags",
      "ip,203.0.113.55,e2e,0.85,malware",
      "domain,preview.example.invalid,e2e,0.7,phishing",
    ].join("\n");
    await notebook.importModal.pasteInput.fill(csv);

    await expect(notebook.importModal.preview).toBeVisible();
    await expect(notebook.importModal.previewTable).toBeVisible();
    // Both data rows should be in the preview.
    await expect(notebook.importModal.previewTable).toContainText(
      "203.0.113.55",
    );
    await expect(notebook.importModal.previewTable).toContainText(
      "preview.example.invalid",
    );
  });

  test("pasting invalid CSV results in zero valid rows (submit disabled)", async ({
    analystPage,
  }) => {
    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();

    // Clearly invalid: bogus type column, no value column.
    const bad = [
      "type,value,source,confidence,tags",
      "not_a_real_type,,manual,0.1,",
    ].join("\n");
    await notebook.importModal.pasteInput.fill(bad);

    // The preview still renders (so the user can see the error rows),
    // but the submit button is disabled because no row is valid.
    await expect(notebook.importModal.preview).toBeVisible();
    await expect(notebook.importModal.submitButton).toBeDisabled();
  });

  test("submitting valid CSV creates IOCs (verified via analystApi)", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { investigation } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Import target ${stamp}`,
      iocs: [],
    });
    const beforeCount = (await analystApi.listIOCs(investigation.id)).length;

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();

    // Bind the import to the seeded investigation so listIOCs picks
    // it up.
    await notebook.importModal.investigationInput.selectOption(
      investigation.id,
    );

    // Two unique values — keep them inside the e2e namespace so they
    // never collide with other tests.
    const uniqueIp = `198.18.${(stamp >> 8) % 240}.${stamp % 240}`;
    const uniqueDomain = `import-${stamp}.example.invalid`;
    const csv = [
      "type,value,source,confidence,tags",
      `ip,${uniqueIp},e2e,0.85,`,
      `domain,${uniqueDomain},e2e,0.75,`,
    ].join("\n");
    await notebook.importModal.pasteInput.fill(csv);
    await expect(notebook.importModal.submitButton).toBeEnabled();
    await notebook.importModal.submitButton.click();

    await expect(notebook.importModal.result).toBeVisible({ timeout: 15_000 });

    // Verify via the API — the IOCs landed against the seeded
    // investigation.
    const after = await analystApi.listIOCs(investigation.id);
    expect(after.length).toBeGreaterThan(beforeCount);
    expect(after.some((i) => i.value === uniqueIp)).toBe(true);
    expect(after.some((i) => i.value === uniqueDomain)).toBe(true);
  });

  test("cancel closes the modal without creating IOCs", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { investigation } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Cancel import ${stamp}`,
      iocs: [],
    });
    const before = await analystApi.listIOCs(investigation.id);

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.importButton.click();
    await expect(notebook.importModal.root).toBeVisible();

    await notebook.importModal.investigationInput.selectOption(
      investigation.id,
    );
    const csv = [
      "type,value,source,confidence,tags",
      `ip,198.18.99.${stamp % 240},e2e,0.85,`,
    ].join("\n");
    await notebook.importModal.pasteInput.fill(csv);

    await notebook.importModal.cancelButton.click();
    await expect(notebook.importModal.root).toBeHidden();

    // No IOC should have been written.
    const after = await analystApi.listIOCs(investigation.id);
    expect(after.length).toBe(before.length);
  });
});
