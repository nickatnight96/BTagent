/**
 * Workflows detail + launch slice (Phase 4 — Slice B).
 *
 * Seeds a runnable workflow via the backend API (one-node manual-trigger
 * echo, which the run service registers + runs synchronously), then drives
 * the detail page UI to render versions/runs and launch a new run via the
 * dialog.
 *
 * Seeding uses ``page.request`` with the senior persona's cookie because
 * ``workflow:create`` is senior-gated; launching uses the analyst persona
 * because ``workflow:run`` is analyst-gated, mirroring real usage.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";
import { Sidebar } from "../../pages/sidebar";

const ECHO_DEFINITION = {
  name: "echo-wf",
  version: "1.0",
  description: "echo trigger payload",
  trigger: {},
  nodes: [{ step_id: "t1", node_id: "trigger.manual", name: "start", config: {} }],
  edges: [],
};

async function seedRunnableWorkflow(seniorPage: Page, name: string): Promise<string> {
  const resp = await seniorPage.request.post("/api/v1/workflows", {
    data: {
      name,
      description: "Seeded by e2e (slice B)",
      definition: ECHO_DEFINITION,
    },
  });
  expect(resp.ok(), `seed POST failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  const wf = await resp.json();
  return wf.id as string;
}

test.describe("Workflow detail (Phase 4 slice B)", () => {
  test("detail page renders versions + empty run history for a fresh workflow", async ({
    seniorPage,
    analystPage,
  }) => {
    const name = `E2E WF-detail ${Date.now()}`;
    const wfId = await seedRunnableWorkflow(seniorPage, name);

    // Drive the UI as the analyst (workflow:view).
    await analystPage.goto("/");
    const sidebar = new Sidebar(analystPage);
    await sidebar.root.waitFor({ state: "visible", timeout: 15_000 });
    await sidebar.goToWorkflows();
    // Click the card for the workflow we just seeded.
    const card = analystPage.getByTestId("workflow-card").filter({ hasText: name });
    await expect(card).toBeVisible({ timeout: 15_000 });
    await card.click();
    await analystPage.waitForURL(`**/workflows/${wfId}`, { timeout: 5_000 });
    await analystPage.getByTestId("workflow-detail").waitFor({ state: "visible", timeout: 10_000 });

    await expect(analystPage.getByTestId("workflow-name")).toHaveText(name);
    // Initial draft v1 is auto-created by POST /workflows.
    await expect(analystPage.getByTestId("workflow-versions")).toBeVisible();
    await expect(
      analystPage.getByTestId("workflow-version-row").filter({ hasText: "v1" }),
    ).toBeVisible();
    // No runs yet.
    await expect(analystPage.getByTestId("workflow-runs")).toHaveCount(0);
  });

  test("launching v1 records a succeeded run in the history", async ({
    seniorPage,
    analystPage,
  }) => {
    const name = `E2E WF-launch ${Date.now()}`;
    const wfId = await seedRunnableWorkflow(seniorPage, name);

    await analystPage.goto(`/workflows/${wfId}`);
    await analystPage.getByTestId("workflow-detail").waitFor({ state: "visible", timeout: 10_000 });

    // Open the launch dialog and run.
    await analystPage.getByTestId("workflow-launch-open").click();
    await expect(analystPage.getByTestId("launch-version-select")).toBeVisible();
    // Provide a non-empty payload so the echo trigger has something to echo.
    await analystPage.getByTestId("launch-payload").fill('{"payload":{"hello":"world"}}');
    await analystPage.getByTestId("launch-submit").click();

    // The run appears with status=succeeded (advisory-tier echo trigger runs sync).
    // ``data-run-status`` lives on the <li data-testid="workflow-run-row"> itself,
    // not on a descendant, so ``.filter({ has: ... })`` would not match; query
    // the attribute on the row element directly.
    const runs = analystPage.getByTestId("workflow-runs");
    await expect(runs).toBeVisible({ timeout: 20_000 });
    const succeededRun = analystPage.locator(
      '[data-testid="workflow-run-row"][data-run-status="succeeded"]',
    );
    await expect(succeededRun.first()).toBeVisible({ timeout: 20_000 });
  });
});
