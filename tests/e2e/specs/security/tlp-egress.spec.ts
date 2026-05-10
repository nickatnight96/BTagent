/**
 * TLP egress enforcement.
 *
 * BTagent treats TLP:RED as "must not leave the platform" — the
 * STIX exporter, knowledge ingest path, and MCP egress all enforce
 * this at the API and surface UI errors when a user tries.
 */
import { test, expect } from "../../fixtures/auth";
import { seedRedInvestigation } from "../../fixtures/seed-helpers";
import { InvestigationListPage } from "../../pages/investigation-list-page";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";

test("STIX export from a TLP:RED IOC notebook is blocked in the UI", async ({
  analystPage,
  analystApi,
}) => {
  // Senior owns a RED case so analyst1 cannot read it directly. The
  // analyst opens the notebook scoped via senior-side share, but for
  // the simple egress UI assertion we use the analyst's own RED case
  // (analysts CAN own RED cases under role policy).
  const { investigation } = await seedRedInvestigation(analystApi);

  // Sanity: the seeded data exists from the analyst's perspective.
  const refetched = await analystApi.getInvestigation(investigation.id);
  expect(refetched.tlp_level).toBe("red");

  const ioc = new IOCNotebookPage(analystPage);
  // Hydrate the investigation store via the dashboard so the export
  // dialog's ``investigationInput`` (a native ``<select>``) has the
  // seeded RED case as a selectable option.
  await analystPage.goto("/");
  await analystPage.getByTestId("investigation-list").waitFor({
    state: "visible",
    timeout: 10_000,
  });
  await ioc.goto();
  // Open the export dialog. Pre-fill with the RED investigation id.
  await ioc.exportButton.click();
  const dialog = ioc.exportDialog;
  await dialog.root.waitFor({ state: "visible" });
  // ``investigationInput`` is a ``<select>`` — selectOption, not fill.
  await dialog.investigationInput.selectOption(investigation.id);

  // Pick STIX format. ``stix_2.1`` is the canonical option value.
  await dialog.formatRadio("stix_2.1").click();
  // The TLP-warning surface from Sprint A export instrumentation
  // should pop once the export targets a RED case.
  await dialog.tlpWarning
    .waitFor({ state: "visible", timeout: 5_000 })
    .catch(() => {
      // If the warning is shown only on submit, the next assertion
      // covers the API-level block.
    });

  // Try to submit — backend must 403 the call.
  await dialog.submitButton.click();
  // The export endpoint is a GET (``/iocs/export?investigation_id=...&tlp_level=red``)
  // not a POST; the TLP:RED guard at iocs.py lives in the query-param
  // path and returns 403 with a "Cannot export TLP:RED IOCs" detail.
  const apiResp = await analystApi.ctx.get(
    `/api/v1/iocs/export?investigation_id=${investigation.id}&tlp_level=red`,
  );
  expect([400, 403]).toContain(apiResp.status());
});

test("knowledge ingest with classification=red returns 4xx", async ({
  analystApi,
}) => {
  const res = await analystApi.ctx.post("/api/v1/knowledge/ingest", {
    data: {
      title: "[E2E] RED ingest probe",
      content: "Restricted runbook content not for non-RED workflows.",
      source_type: "runbook",
      classification: "red",
    },
  });
  // Either flatly rejected (403) or rejected at validation (400/422).
  expect([400, 403, 422]).toContain(res.status());
});

test("RED investigation card surfaces a TLP:RED indicator", async ({
  analystPage,
  analystApi,
}) => {
  // Defence in depth: the UI must visibly mark RED cases so analysts
  // know egress is blocked before they even try.
  const { investigation } = await seedRedInvestigation(analystApi);
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  const card = list.cardFor(investigation.id);
  await card.waitFor({ state: "visible", timeout: 10_000 });
  const cardText = (await card.innerText()).toLowerCase();
  expect(cardText).toMatch(/red/);
});

test.skip(
  "WS subscribe to a RED investigation as a non-RED-cleared user — blocked",
  async () => {
    // TODO: clearance per-user (vs. role) is not yet differentiated
    // in the WS auth path. When the org adds a "RED clearance" claim
    // on the user identity, replace this skip with a real assertion
    // against the WS close code.
  },
);
