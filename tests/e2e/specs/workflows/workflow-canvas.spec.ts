/**
 * Workflows read-only canvas slice (Phase 4 — Slice C).
 *
 * Seeds a one-node manual-trigger workflow via the senior persona's request
 * session, then drives the detail page → "View canvas" link as the analyst
 * to verify ReactFlow renders the engine graph definition end-to-end.
 *
 * Authoring (drag/drop palette, config panel, save-as-new-draft) is slice D.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";

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
      description: "Seeded by e2e (slice C)",
      definition: ECHO_DEFINITION,
    },
  });
  expect(resp.ok(), `seed POST failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  const wf = await resp.json();
  return wf.id as string;
}

test.describe("Workflow canvas (Phase 4 slice C, read-only)", () => {
  test("opens canvas from detail and renders the single trigger node", async ({
    seniorPage,
    analystPage,
  }) => {
    const name = `E2E WF-canvas ${Date.now()}`;
    const wfId = await seedRunnableWorkflow(seniorPage, name);

    // Drive the UI as analyst (workflow:view).
    await analystPage.goto(`/workflows/${wfId}`);
    await analystPage.getByTestId("workflow-detail").waitFor({ state: "visible", timeout: 10_000 });

    // Click the "View canvas" affordance on v1.
    const canvasLink = analystPage
      .getByTestId("workflow-version-canvas-link")
      .filter({ has: analystPage.locator('[data-version-number="1"]') })
      .first()
      .or(analystPage.getByTestId("workflow-version-canvas-link").first());
    await canvasLink.click();
    await analystPage.waitForURL(`**/workflows/${wfId}/versions/1/canvas`, {
      timeout: 5_000,
    });

    // The canvas surface mounts.
    await expect(analystPage.getByTestId("workflow-canvas")).toBeVisible({
      timeout: 10_000,
    });
    // Read-only chip is shown.
    await expect(analystPage.getByText(/read-only/i)).toBeVisible();
    // ReactFlow mounts the flow container (one node => non-empty branch).
    await expect(analystPage.getByTestId("workflow-canvas-flow")).toBeVisible({
      timeout: 10_000,
    });
    // ReactFlow internally renders a `.react-flow__node` element per node.
    await expect(analystPage.locator(".react-flow__node").first()).toBeVisible({
      timeout: 10_000,
    });
  });
});
