/**
 * IOC bulk actions — select-all, bulk-enrich, bulk-export, bulk-clear.
 *
 * Sprint E. The bulk-actions toolbar appears only when at least one
 * row is selected, so the visibility tests assert the show/hide
 * contract as well as the action behaviours.
 */
import { test, expect } from "../../fixtures/auth";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test.describe("IOC bulk actions", () => {
  test("select-all checkbox selects every visible row", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Bulk select-all ${stamp}`,
      iocs: [
        { type: "ip", value: `198.18.40.${stamp % 240}` },
        { type: "ip", value: `198.18.41.${stamp % 240}` },
        { type: "domain", value: `bulk-${stamp}.example.invalid` },
      ],
    });

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    // Bulk bar starts hidden.
    await expect(notebook.bulkActions).toBeHidden();

    await notebook.selectAll.click();
    // The bulk-actions bar appears once any row is selected.
    await expect(notebook.bulkActions).toBeVisible();
    // Select-all is a native checkbox — its checked attribute should
    // flip true.
    await expect(notebook.selectAll).toBeChecked();
  });

  test("bulk-enrich button is hidden when no rows selected; visible when >=1", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Bulk visibility ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.42.${stamp % 240}` }],
    });

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await expect(notebook.bulkEnrichButton).toBeHidden();

    await notebook.selectAll.click();
    await expect(notebook.bulkEnrichButton).toBeVisible();
  });

  test("bulk-clear deselects all rows", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Bulk clear ${stamp}`,
      iocs: [
        { type: "ip", value: `198.18.43.${stamp % 240}` },
        { type: "ip", value: `198.18.44.${stamp % 240}` },
      ],
    });

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.selectAll.click();
    await expect(notebook.bulkActions).toBeVisible();
    await expect(notebook.selectAll).toBeChecked();

    await notebook.bulkClearButton.click();
    // Bar disappears (no selection) and the checkbox unticks.
    await expect(notebook.bulkActions).toBeHidden();
    await expect(notebook.selectAll).not.toBeChecked();
  });

  test("bulk-enrich queues enrichment for selected IOCs", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Bulk enrich ${stamp}`,
      iocs: [
        { type: "ip", value: `198.18.45.${stamp % 240}` },
        { type: "ip", value: `198.18.46.${stamp % 240}` },
      ],
    });

    // Mock the bulk-enrich endpoint so the test is hermetic — assert
    // the request was issued with the selected IDs in the payload.
    let bulkPayload: { ids?: string[] } | null = null;
    await analystPage.route(
      "**/api/v1/iocs/bulk-enrich",
      async (route, req) => {
        try {
          bulkPayload = req.postDataJSON() as { ids?: string[] };
        } catch {
          bulkPayload = null;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ results: [] }),
        });
      },
    );

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.selectAll.click();
    await notebook.bulkEnrichButton.click();

    // Wait until the mocked endpoint has been hit at least once.
    await expect
      .poll(() => (bulkPayload as { ids?: string[] } | null)?.ids?.length ?? 0)
      .toBeGreaterThan(0);
    const captured = bulkPayload as { ids?: string[] } | null;
    expect(Array.isArray(captured?.ids)).toBe(true);
    expect((captured?.ids ?? []).length).toBeGreaterThan(0);
  });

  test("bulk-export opens the export dialog", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Bulk export ${stamp}`,
      iocs: [
        { type: "ip", value: `198.18.47.${stamp % 240}` },
        { type: "ip", value: `198.18.48.${stamp % 240}` },
      ],
    });

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.selectAll.click();
    await expect(notebook.bulkExportButton).toBeVisible();

    await notebook.bulkExportButton.click();
    // Bulk-export reuses the IOCExportDialog component, so the same
    // POM locator applies. Pre-filtering of selected IOCs is asserted
    // in tlp-egress.spec.ts; here we just confirm the dialog opened.
    // TODO(sprintE): expose a "selected only" indicator inside the
    // export dialog so a test can assert the pre-filter without
    // relying on the bundle contents.
    await expect(notebook.exportDialog.root).toBeVisible();
  });
});
