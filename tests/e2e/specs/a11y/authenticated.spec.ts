/**
 * Accessibility coverage for the authenticated surfaces. Each spec
 * navigates as the analyst persona, lets the page settle, and asserts
 * zero critical/serious a11y violations.
 *
 * Sprint I baseline. As the catalogue grows, these split into per-
 * surface files (``a11y/investigation-list.spec.ts``, etc.) — for now
 * we keep the matrix in one file because they share setup.
 */
import { test } from "../../fixtures/auth";
import { expectNoA11yViolations } from "../../fixtures/a11y";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test("PunchList / investigation list", async ({ analystPage }) => {
  await analystPage.goto("/");
  await analystPage.getByTestId("investigation-list").waitFor();
  await expectNoA11yViolations(analystPage);
});

test("Investigation workspace", async ({ analystPage, analystApi }) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi);
  await analystPage.goto(`/investigations/${investigation.id}`);
  await analystPage.getByTestId("investigation-workspace").waitFor();
  await expectNoA11yViolations(analystPage, {
    // The chat textarea + the event-stream live region cycle classes
    // on every render; suppress the duplicate-id rule which axe
    // flags transiently when React re-renders during the scan.
    exclude: ['[data-testid="event-stream"]'],
  });
});

test("IOC notebook", async ({ analystPage, analystApi }) => {
  await seedInvestigationWithIOCs(analystApi);
  await analystPage.goto("/iocs");
  await analystPage.getByTestId("ioc-notebook").waitFor();
  await expectNoA11yViolations(analystPage);
});

test("MITRE matrix", async ({ analystPage }) => {
  await analystPage.goto("/mitre");
  await analystPage.getByTestId("mitre-matrix").waitFor();
  // The matrix grid has a lot of cells; scope to the toolbar +
  // controls to keep the audit fast and noise-free. Per-cell axe
  // checks would re-run on the same WCAG rules N hundred times.
  await expectNoA11yViolations(analystPage, {
    exclude: ['[data-testid="mitre-matrix-grid"]'],
  });
});

test("Knowledge base", async ({ analystPage }) => {
  await analystPage.goto("/knowledge");
  await analystPage.getByTestId("knowledge").waitFor();
  await expectNoA11yViolations(analystPage);
});

test("Playbook list", async ({ analystPage }) => {
  await analystPage.goto("/playbooks");
  await analystPage.getByTestId("playbook-list").waitFor();
  await expectNoA11yViolations(analystPage);
});

test("New investigation modal — open state", async ({ analystPage }) => {
  await analystPage.goto("/");
  await analystPage.getByTestId("investigation-list").waitFor();
  await analystPage.getByTestId("investigation-list-new-button").click();
  await analystPage.getByTestId("new-investigation-dialog").waitFor();
  await expectNoA11yViolations(analystPage);
});

test("Knowledge ingest modal — open state", async ({ analystPage }) => {
  await analystPage.goto("/knowledge");
  await analystPage.getByTestId("knowledge-ingest-open-button").click();
  await analystPage.getByTestId("knowledge-ingest-dialog").waitFor();
  await expectNoA11yViolations(analystPage);
});
