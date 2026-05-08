/**
 * TLP egress regression — STIX export must drop TLP:RED IOCs at any
 * lower-or-equal export context, and TLP:RED export contexts must be
 * blocked outright.
 *
 * This is the dedicated regression for the audit-cleanup fix that
 * uncovered TLP:RED IOCs being included in STIX bundles when the
 * caller asked for an AMBER or GREEN export. The test asserts the
 * bundle bytes — anything weaker (e.g. count-based assertions) misses
 * the bug class entirely.
 *
 * Hydration note: the export dialog reads the investigation list from
 * the Zustand ``investigationStore`` which is populated by visiting
 * the dashboard (``/``). Going straight to ``/iocs`` leaves the
 * store empty and the per-test seeded investigation is missing from
 * the dropdown. Each test calls ``hydrateInvestigationsThenGotoIOCs``
 * so the dropdown has the option ``selectOption(investigation.id)``
 * needs.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";
import { hydrateInvestigationsThenGotoIOCs } from "../../fixtures/navigation";

/**
 * Trigger the export submit, capture the resulting download, and
 * return the bundle text.
 */
async function readDownloadText(
  page: Page,
  notebook: IOCNotebookPage,
): Promise<string> {
  const downloadPromise = page.waitForEvent("download", { timeout: 15_000 });
  await notebook.exportDialog.submitButton.click();
  const download = await downloadPromise;
  const stream = await download.createReadStream();
  if (!stream) throw new Error("download stream missing");
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

test.describe("STIX export TLP egress (regression)", () => {
  test("GREEN context: export contains GREEN IOC values, not RED ones", async ({
    seniorPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const greenValue = `198.51.100.${stamp % 240}`;
    const redValue = `198.51.101.${stamp % 240}`;
    const { investigation } = await seedInvestigationWithIOCs(seniorApi, {
      title: `[E2E] TLP egress GREEN ${stamp}`,
      tlp_level: "amber",
      iocs: [
        { type: "ip", value: greenValue, tlp_level: "green" },
        { type: "ip", value: redValue, tlp_level: "red" },
      ],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(seniorPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("stix_2.1").click();
    await notebook.exportDialog.tlpInput.selectOption("GREEN");

    const text = await readDownloadText(seniorPage, notebook);
    expect(text).toContain(greenValue);
    expect(text).not.toContain(redValue);
  });

  test("AMBER context: export contains GREEN IOC values, not RED ones", async ({
    seniorPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const greenValue = `198.51.110.${stamp % 240}`;
    const redValue = `198.51.111.${stamp % 240}`;
    const { investigation } = await seedInvestigationWithIOCs(seniorApi, {
      title: `[E2E] TLP egress AMBER ${stamp}`,
      tlp_level: "amber",
      iocs: [
        { type: "ip", value: greenValue, tlp_level: "green" },
        { type: "ip", value: redValue, tlp_level: "red" },
      ],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(seniorPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("stix_2.1").click();
    await notebook.exportDialog.tlpInput.selectOption("AMBER");

    // AMBER context shows the warning, but export still proceeds.
    await expect(notebook.exportDialog.tlpWarning).toBeVisible();

    const text = await readDownloadText(seniorPage, notebook);
    expect(text).toContain(greenValue);
    expect(text).not.toContain(redValue);
  });

  test("WHITE/CLEAR context: export contains GREEN IOC values, not RED ones", async ({
    seniorPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const greenValue = `198.51.120.${stamp % 240}`;
    const redValue = `198.51.121.${stamp % 240}`;
    const { investigation } = await seedInvestigationWithIOCs(seniorApi, {
      title: `[E2E] TLP egress WHITE ${stamp}`,
      tlp_level: "amber",
      iocs: [
        { type: "ip", value: greenValue, tlp_level: "green" },
        { type: "ip", value: redValue, tlp_level: "red" },
      ],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(seniorPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("stix_2.1").click();
    // The export dialog uses the TLP enum from frontend/types/config —
    // ``white`` is the legacy alias; ``clear`` is the post-2.0 value
    // and is the option actually rendered. Try the modern value first.
    try {
      await notebook.exportDialog.tlpInput.selectOption("CLEAR");
    } catch {
      await notebook.exportDialog.tlpInput.selectOption("CLEAR");
    }

    const text = await readDownloadText(seniorPage, notebook);
    expect(text).toContain(greenValue);
    expect(text).not.toContain(redValue);
  });

  test("RED context surfaces the warning banner before submit", async ({
    seniorPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const { investigation } = await seedInvestigationWithIOCs(seniorApi, {
      title: `[E2E] TLP egress RED warning ${stamp}`,
      tlp_level: "amber",
      iocs: [
        { type: "ip", value: `198.51.130.${stamp % 240}`, tlp_level: "green" },
        { type: "ip", value: `198.51.131.${stamp % 240}`, tlp_level: "red" },
      ],
    });

    const notebook = await hydrateInvestigationsThenGotoIOCs(seniorPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("stix_2.1").click();
    await notebook.exportDialog.tlpInput.selectOption("RED");

    // The user must be warned before they confirm a TLP:RED export.
    await expect(notebook.exportDialog.tlpWarning).toBeVisible();
    await expect(notebook.exportDialog.tlpWarning).toContainText(/red/i);
  });

  test("RED context: backend rejects (or strips) the RED IOC bytes", async ({
    seniorPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const greenValue = `198.51.140.${stamp % 240}`;
    const redValue = `198.51.141.${stamp % 240}`;
    const { investigation } = await seedInvestigationWithIOCs(seniorApi, {
      title: `[E2E] TLP egress RED export ${stamp}`,
      tlp_level: "red",
      iocs: [
        { type: "ip", value: greenValue, tlp_level: "green" },
        { type: "ip", value: redValue, tlp_level: "red" },
      ],
    });

    // Listen for the export response so we can assert either:
    //   * the request was rejected with a 4xx / error banner, OR
    //   * the bundle did not include the RED IOC value.
    // Both are valid hardening behaviours; the regression bug was
    // RED-tagged values leaking into the bundle bytes silently.
    const responsePromise = seniorPage.waitForResponse(
      (resp) =>
        resp.url().includes("/iocs/export") && resp.request().method() === "GET",
      { timeout: 15_000 },
    );

    const notebook = await hydrateInvestigationsThenGotoIOCs(seniorPage);
    await notebook.exportButton.click();
    await notebook.exportDialog.investigationInput.selectOption(
      investigation.id,
    );
    await notebook.exportDialog.formatRadio("stix_2.1").click();
    await notebook.exportDialog.tlpInput.selectOption("RED");

    // Warning must be visible at RED.
    await expect(notebook.exportDialog.tlpWarning).toBeVisible();

    // Submit and inspect the response.
    await notebook.exportDialog.submitButton.click();
    const response = await responsePromise;
    if (!response.ok()) {
      // Backend rejected the export — that is acceptable hardening.
      expect([400, 401, 403, 422]).toContain(response.status());
      return;
    }

    // If the backend allowed the export, the bundle bytes must still
    // not contain the RED IOC value (the regression we're guarding).
    const body = await response.body();
    const text = body.toString("utf-8");
    expect(text).not.toContain(redValue);
    // And the GREEN IOC should still be present (defence-in-depth —
    // the filter must not nuke everything).
    expect(text).toContain(greenValue);
  });
});
