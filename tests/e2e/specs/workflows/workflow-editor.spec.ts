/**
 * Workflow authoring editor slice (Phase 4 — Slice D).
 *
 * Verifies the editor mounts on a real workflow draft, renders the node
 * palette populated from the backend node-catalog endpoint, mounts the
 * ReactFlow canvas with the existing definition's nodes, and the Save
 * button is reachable. Drag/drop is intentionally NOT exercised in
 * Playwright -- HTML5 drag events don't fire on synthetic mouse moves
 * across all browsers, so the interaction is covered as a unit-level
 * concern by future vitest cases on flowToDefinition. The wiring here
 * is the contract test: palette + canvas + save button all render
 * against live endpoints.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";

const ECHO_DEFINITION = {
  name: "echo-wf",
  version: "1.0",
  trigger: {},
  nodes: [{ step_id: "t1", node_id: "trigger.manual", name: "start", config: {} }],
  edges: [],
};

async function seedDraft(seniorPage: Page, name: string): Promise<string> {
  const resp = await seniorPage.request.post("/api/v1/workflows", {
    data: {
      name,
      description: "Seeded by e2e (slice D)",
      definition: ECHO_DEFINITION,
    },
  });
  expect(resp.ok(), `seed failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
  return (await resp.json()).id as string;
}

test.describe("Workflow editor (Phase 4 slice D)", () => {
  test("editor mounts with palette + canvas for a draft version", async ({
    seniorPage,
  }) => {
    const name = `E2E WF-editor ${Date.now()}`;
    const wfId = await seedDraft(seniorPage, name);

    // workflow:edit is a senior_analyst capability, so drive as senior.
    await seniorPage.goto(`/workflows/${wfId}/versions/1/edit`);
    await seniorPage
      .getByTestId("workflow-editor")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Palette + canvas mount.
    await expect(seniorPage.getByTestId("workflow-editor-palette")).toBeVisible();
    await expect(seniorPage.getByTestId("workflow-editor-canvas")).toBeVisible();

    // Palette is populated from /workflows/node-catalog -- expect the
    // manual trigger to be present (the catalog import chain registers it).
    // ``data-node-id`` lives on the palette item element itself (not a
    // descendant), so query the attribute on the testid element directly.
    const manualPaletteItem = seniorPage.locator(
      '[data-testid="palette-item"][data-node-id="trigger.manual"]',
    );
    await expect(manualPaletteItem.first()).toBeVisible({ timeout: 10_000 });

    // ReactFlow rendered the seeded "t1" trigger node.
    await expect(seniorPage.locator(".react-flow__node").first()).toBeVisible({
      timeout: 10_000,
    });

    // Save button exists and is clickable on a draft.
    const save = seniorPage.getByTestId("workflow-editor-save");
    await expect(save).toBeVisible();
    await expect(save).toBeEnabled();
  });

  test("clicking a node opens the config panel with schema form + JSON toggle", async ({
    seniorPage,
  }) => {
    const name = `E2E WF-editor-cfg ${Date.now()}`;
    const wfId = await seedDraft(seniorPage, name);
    await seniorPage.goto(`/workflows/${wfId}/versions/1/edit`);
    await seniorPage
      .getByTestId("workflow-editor")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Click the ReactFlow-rendered node.
    await seniorPage.locator(".react-flow__node").first().click();

    // Config panel is populated with the seeded step id "t1".
    await expect(seniorPage.getByTestId("workflow-editor-config-form")).toBeVisible();
    await expect(seniorPage.getByTestId("workflow-editor-step-id")).toHaveValue("t1");

    // trigger.manual has a renderable input_schema (a "payload" object
    // field), so the typed form is the default config view…
    await expect(seniorPage.getByTestId("schema-config-form")).toBeVisible();
    await expect(seniorPage.getByTestId("schema-field-payload")).toBeVisible();

    // …and the raw JSON textarea is reachable via the JSON toggle.
    await seniorPage.getByTestId("workflow-editor-config-mode-json").click();
    await expect(seniorPage.getByTestId("workflow-editor-config-json")).toBeVisible();
    await expect(seniorPage.getByTestId("workflow-editor-config-json")).toHaveValue("{}");

    // Toggling back restores the form.
    await seniorPage.getByTestId("workflow-editor-config-mode-form").click();
    await expect(seniorPage.getByTestId("schema-config-form")).toBeVisible();
  });
});
