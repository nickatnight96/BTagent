/**
 * IOC detail panel — open / value / enrich / investigation link / close.
 *
 * Sprint E. The enrichment test mocks ``/api/v1/iocs/<id>/enrich`` via
 * ``page.route`` so we don't depend on the live CTI providers (and so
 * we can be deterministic about which sections render).
 */
import { test, expect } from "../../fixtures/auth";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test.describe("IOC detail panel", () => {
  test("clicking an IOC row opens the detail panel", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { iocs } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Detail open ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.30.${stamp % 240}` }],
    });
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.root).toBeVisible();
  });

  test("detail panel shows the IOC value", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const value = `198.18.31.${stamp % 240}`;
    const { iocs } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Detail value ${stamp}`,
      iocs: [{ type: "ip", value }],
    });
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.value).toHaveText(value);
  });

  test("enrich button triggers enrichment and CTI sections become visible", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { iocs } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Detail enrich ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.32.${stamp % 240}` }],
    });
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    // Mock the enrich endpoint so the test is hermetic — we control
    // the exact CTI shape returned, and we don't burn quota on real
    // VirusTotal / Shodan keys.
    await analystPage.route(
      new RegExp(`/api/v1/iocs/${target.id}/enrich`),
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            ...target,
            enrichment_status: "enriched",
            enrichment_data: {
              virus_total: {
                positives: 7,
                total: 75,
                reputation: -42,
                last_analysis_date: new Date().toISOString(),
              },
              shodan: {
                ports: [22, 80, 443],
                vulns: ["CVE-2024-12345"],
                isp: "FakeNet",
                city: "Nowhere",
                country: "ZZ",
              },
              grey_noise: {
                classification: "malicious",
                noise: true,
                riot: false,
              },
              abuse_ipdb: {
                abuse_confidence_score: 92,
                total_reports: 31,
                isp: "FakeNet",
                usage_type: "Data Center/Web Hosting/Transit",
              },
              raw_results: [],
            },
          }),
        });
      },
    );

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.root).toBeVisible();

    await notebook.detailPanel.enrichButton.click();

    // Each CTI section should render once the mocked response lands.
    await expect(notebook.detailPanel.virustotal).toBeVisible({
      timeout: 10_000,
    });
    await expect(notebook.detailPanel.shodan).toBeVisible();
    await expect(notebook.detailPanel.greynoise).toBeVisible();
    await expect(notebook.detailPanel.abuseipdb).toBeVisible();
  });

  test("investigation link navigates to the parent investigation workspace", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { investigation, iocs } = await seedInvestigationWithIOCs(
      analystApi,
      {
        title: `[E2E] Detail nav ${stamp}`,
        iocs: [{ type: "ip", value: `198.18.33.${stamp % 240}` }],
      },
    );
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.investigationLink).toBeVisible();

    await notebook.detailPanel.investigationLink.click();
    await analystPage.waitForURL(`**/investigations/${investigation.id}`, {
      timeout: 10_000,
    });
    expect(analystPage.url()).toContain(`/investigations/${investigation.id}`);
  });

  test("close button hides the panel", async ({ analystPage, analystApi }) => {
    const stamp = Date.now();
    const { iocs } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Detail close ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.34.${stamp % 240}` }],
    });
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.root).toBeVisible();

    await notebook.detailPanel.closeButton.click();
    await expect(notebook.detailPanel.root).toBeHidden();
  });

  test("backdrop click also closes the panel", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    const { iocs } = await seedInvestigationWithIOCs(analystApi, {
      title: `[E2E] Detail backdrop ${stamp}`,
      iocs: [{ type: "ip", value: `198.18.35.${stamp % 240}` }],
    });
    const target = iocs[0];
    if (!target) throw new Error("seed must produce an IOC");

    const notebook = new IOCNotebookPage(analystPage);
    await notebook.goto();
    await notebook.row(target.id).click();
    await expect(notebook.detailPanel.root).toBeVisible();

    // Backdrop is a sibling of the slide-over and intercepts clicks
    // off the panel. The component wires its onClick to the close
    // handler; if the build under test ever drops that wiring, this
    // assertion will catch it.
    await notebook.detailPanel.backdrop.click({ force: true });
    await expect(notebook.detailPanel.root).toBeHidden();
  });
});
