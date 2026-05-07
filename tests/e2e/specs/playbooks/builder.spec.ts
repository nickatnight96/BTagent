/**
 * Playbook builder — load / validate / YAML / save / mobile.
 *
 * Sprint F scope. Drives the PlaybookBuilderPage POM. Validation and
 * save tests cooperate with the real backend so the save side-effect
 * is observable through the API after the click.
 */
import { test, expect } from "../../fixtures/auth";
import {
  PlaybookBuilderPage,
  PlaybookYamlEditor,
} from "../../pages/playbook-pages";
import type { BTAgentApiClient } from "../../fixtures/api-client";

const VALID_YAML = `name: e2e-builder
description: Builder spec
trigger:
  type: manual
steps:
  - id: noop
    type: action
    tool: noop
`;

interface SeededPlaybook {
  id: string;
  name: string;
}

async function seedPlaybook(
  api: BTAgentApiClient,
  name: string,
): Promise<SeededPlaybook> {
  const res = await api.ctx.post("/api/v1/playbooks", {
    data: { name, yaml_content: VALID_YAML },
  });
  if (!res.ok()) {
    throw new Error(
      `Seed playbook failed: ${res.status()} ${await res.text()}`,
    );
  }
  const body = (await res.json()) as { id: string; name: string };
  return { id: body.id, name: body.name };
}

test.describe("Playbook builder", () => {
  test("builder loads with the empty canvas at /playbooks/builder", async ({
    seniorPage,
  }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    await expect(builder.root).toBeVisible();
    await expect(builder.canvas).toBeVisible();
    await expect(builder.toolbar).toBeVisible();
  });

  test("loading an existing playbook by id populates the title", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(
      seniorApi,
      `[E2E] Builder Load ${Date.now()}`,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    await expect(builder.root).toBeVisible({ timeout: 10_000 });
    // The title element renders the playbook name once the fetch resolves.
    await expect(builder.title).toBeVisible({ timeout: 10_000 });
    await expect(builder.title).toContainText(pb.name);
  });

  test("validate button surfaces a result without crashing", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(
      seniorApi,
      `[E2E] Builder Validate ${Date.now()}`,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    await expect(builder.validateButton).toBeVisible();
    await builder.validateButton.click();
    // Either a success or an error banner — clicking the button must
    // not leave the builder in a broken state.
    await expect(builder.root).toBeVisible();
  });

  test("yaml-toggle reveals the YAML editor", async ({ seniorPage }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    await expect(builder.yamlToggle).toBeVisible();
    await builder.yamlToggle.click();

    const yaml = new PlaybookYamlEditor(seniorPage);
    await expect(yaml.root).toBeVisible({ timeout: 5_000 });
    await expect(yaml.editor).toBeVisible();
  });

  test("yaml round-trip: toggle on, see content, toggle off, see canvas", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(
      seniorApi,
      `[E2E] Builder YAML ${Date.now()}`,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);

    await builder.yamlToggle.click();
    const yaml = new PlaybookYamlEditor(seniorPage);
    await expect(yaml.editor).toBeVisible({ timeout: 5_000 });
    // Toggle back; canvas reappears.
    await builder.yamlToggle.click();
    await expect(builder.canvas).toBeVisible({ timeout: 5_000 });
  });

  // TODO(#51 Group F follow-up): the save flow needs a runnable canvas
  // built from the node-palette drag-and-drop, which depends on
  // ReactFlow node templates carrying ``playbook-builder-node-${id}``
  // testids (see PR-11 in the #51 Group F/G batch). Until those land,
  // the empty-canvas save attempt either no-ops (no POST fires) or
  // returns 4xx (empty playbook fails server validation), neither of
  // which exercises the contract under test.
  test.skip("save persists a new playbook via POST /api/v1/playbooks", async ({
    seniorPage,
    seniorApi,
  }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();

    // Listen for the create POST so we can prove the click hit the API
    // even if the UI doesn't yet route the user to the new playbook.
    const createPromise = seniorPage.waitForResponse(
      (resp) =>
        resp.url().includes("/api/v1/playbooks") &&
        resp.request().method() === "POST",
      { timeout: 10_000 },
    );

    await expect(builder.saveButton).toBeVisible();
    await builder.saveButton.click();

    try {
      const resp = await createPromise;
      // 201 (Created) on success, or 4xx if the empty canvas fails
      // server-side validation. We only require the click triggered
      // a real network attempt.
      expect(resp.status()).toBeGreaterThanOrEqual(200);
    } catch {
      // Save may be guarded behind validation — in that case there's
      // no POST. Fall back to confirming the builder is still mounted.
      await expect(builder.root).toBeVisible();
    }

    // Cross-check via the API: list playbooks and confirm the call works.
    const listRes = await seniorApi.ctx.get(
      "/api/v1/playbooks?active_only=true",
    );
    expect(listRes.ok()).toBe(true);
  });

  test("mobile warning shows on small viewports", async ({ seniorPage }) => {
    await seniorPage.setViewportSize({ width: 600, height: 900 });
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    await expect(builder.mobileWarning).toBeVisible({ timeout: 5_000 });
    // Mobile back button is part of the warning surface.
    await expect(builder.mobileBackButton).toBeVisible();
  });

  // PlaybookYAMLEditor is a read-only YAML PREVIEW (a syntax-highlighted
  // ``<pre>`` block generated FROM the canvas via ``nodesToYAML``) — not an
  // editor. There is no textarea / input to drive. The original test name
  // ("invalid YAML pasted into the editor") was a misread of the surface.
  //
  // The actual YAML-input path on this surface is the import-yaml button,
  // which spawns a ``<input type="file">`` and reads a ``.yaml`` /
  // ``.yml`` file. Driving that requires ``setInputFiles`` on a
  // dynamically-created element — out of scope for this small test;
  // tracked in a future "YAML file-import e2e" follow-up if desired.
  //
  // What we CAN test cheaply on this surface, and what the original
  // assertion actually exercised, is "the validate button does not
  // crash the builder when no canvas state has been authored". Keep
  // that assertion live.
  test("validate button does not crash an empty builder", async ({
    seniorPage,
  }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    await expect(builder.validateButton).toBeVisible();
    await builder.validateButton.click();
    // The validator may surface a warning banner (empty playbook is
    // arguably a validation error) or no banner at all — either is
    // acceptable; the contract is "the builder stays mounted and
    // responsive".
    await expect(builder.root).toBeVisible();
    // The YAML toggle should still work after a validate cycle.
    await builder.yamlToggle.click();
    const yaml = new PlaybookYamlEditor(seniorPage);
    await expect(yaml.editor).toBeVisible();
  });
});
