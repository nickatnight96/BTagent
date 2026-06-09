/**
 * Workflow paused-run resume slice (Phase-4 follow-up #1).
 *
 * Seeds a workflow that pauses at a HITL-gated integration node
 * (crowdstrike.isolate_host), launches it as the analyst (-> paused), then
 * approves + resumes as the senior persona (resume needs hitl:approve) and
 * asserts the run row transitions to succeeded in place.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";

const PAUSING_DEFINITION = {
  name: "pause-wf",
  version: "1.0",
  trigger: {},
  nodes: [
    { step_id: "t1", node_id: "trigger.manual", name: "start", config: {} },
    {
      step_id: "iso",
      node_id: "integration.crowdstrike.isolate_host",
      name: "isolate",
      config: { hostname: "WS-1" },
    },
  ],
  edges: [{ source: "t1", target: "iso", label: "next" }],
};

async function seed(seniorPage: Page, name: string): Promise<string> {
  const resp = await seniorPage.request.post("/api/v1/workflows", {
    data: { name, description: "Seeded by e2e (resume)", definition: PAUSING_DEFINITION },
  });
  expect(resp.ok(), `seed failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  return (await resp.json()).id as string;
}

test.describe("Workflow paused-run resume", () => {
  test("launch pauses, then approve & resume completes the run", async ({
    seniorPage,
    analystPage,
  }) => {
    const name = `E2E WF-resume ${Date.now()}`;
    const wfId = await seed(seniorPage, name);

    // Launch as the analyst (workflow:run) via the detail launch dialog.
    await analystPage.goto(`/workflows/${wfId}`);
    await analystPage.getByTestId("workflow-detail").waitFor({ state: "visible", timeout: 10_000 });
    await analystPage.getByTestId("workflow-launch-open").click();
    await analystPage.getByTestId("launch-submit").click();

    // The run shows as paused, with the resume affordance.
    const pausedRow = analystPage.locator(
      '[data-testid="workflow-run-row"][data-run-status="paused"]',
    );
    await expect(pausedRow.first()).toBeVisible({ timeout: 20_000 });
    // Analyst cannot approve (no hitl:approve) -- the button is present but
    // the action 403s; we drive the actual approval as the senior persona,
    // who holds hitl:approve.

    // Resume as senior: reload the detail page in the senior context.
    await seniorPage.goto(`/workflows/${wfId}`);
    await seniorPage.getByTestId("workflow-detail").waitFor({ state: "visible", timeout: 10_000 });
    const seniorPausedRow = seniorPage.locator(
      '[data-testid="workflow-run-row"][data-run-status="paused"]',
    );
    await expect(seniorPausedRow.first()).toBeVisible({ timeout: 10_000 });

    await seniorPage.getByTestId("workflow-run-resume").first().click();

    // After resume the same run transitions to succeeded.
    const succeededRow = seniorPage.locator(
      '[data-testid="workflow-run-row"][data-run-status="succeeded"]',
    );
    await expect(succeededRow.first()).toBeVisible({ timeout: 20_000 });
  });
});
