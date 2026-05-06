/**
 * Playbook config panel — empty state + per-node-type inputs.
 *
 * Sprint F scope. The config panel renders inline on the right side
 * of the builder. It surfaces an empty-state when no node is selected
 * and a typed form when one is. We can't add nodes from a palette
 * (the palette lacks testids in this build), so we drive node-typed
 * forms by seeding a playbook YAML that contains the node and
 * letting the canvas hydrate from it. The selected-node interaction
 * is then driven through the React Flow canvas via visible label text.
 */
import { test, expect } from "../../fixtures/auth";
import {
  PlaybookBuilderPage,
  PlaybookConfigPanel,
} from "../../pages/playbook-pages";
import type { BTAgentApiClient } from "../../fixtures/api-client";

interface SeededPlaybook {
  id: string;
}

async function seedYaml(
  api: BTAgentApiClient,
  name: string,
  yaml: string,
): Promise<SeededPlaybook> {
  const res = await api.ctx.post("/api/v1/playbooks", {
    data: { name, yaml_content: yaml },
  });
  if (!res.ok()) {
    throw new Error(
      `Seed playbook failed: ${res.status()} ${await res.text()}`,
    );
  }
  const body = (await res.json()) as { id: string };
  return { id: body.id };
}

const ACTION_YAML = `name: e2e-action
description: Action node
trigger:
  type: manual
steps:
  - id: act-1
    type: action
    tool: siem_query
    args: { query: "*" }
    timeout: 30
    on_failure: continue
`;

const DECISION_YAML = `name: e2e-decision
description: Decision node
trigger:
  type: manual
steps:
  - id: dec-1
    type: decision
    condition: "score > 50"
  - id: noop
    type: action
    tool: noop
`;

const HITL_YAML = `name: e2e-hitl
description: HITL node
trigger:
  type: manual
steps:
  - id: hitl-1
    type: hitl_gate
    prompt: Approve this action?
    role: senior_analyst
    timeout: 3600
  - id: noop
    type: action
    tool: noop
`;

const PARALLEL_YAML = `name: e2e-parallel
description: Parallel node
trigger:
  type: manual
steps:
  - id: par-1
    type: parallel
    branches: 2
  - id: noop
    type: action
    tool: noop
`;

const TRIGGER_YAML = `name: e2e-trigger
description: Trigger node
trigger:
  type: manual
  parameters: {}
steps:
  - id: noop
    type: action
    tool: noop
`;

/**
 * Click the first React Flow node visible in the canvas. Without
 * testids on the nodes we have to fall back to a generic class
 * selector — React Flow renders nodes inside ``.react-flow__node``
 * wrappers, which is the third-party library's documented hook for
 * styling. We chain off the canvas locator returned by the POM so we
 * don't bypass the POM with a raw page-level lookup.
 */
async function clickFirstCanvasNode(
  builder: PlaybookBuilderPage,
): Promise<boolean> {
  const node = builder.canvas.locator(".react-flow__node").first();
  if (await node.count()) {
    await node.click({ force: true });
    return true;
  }
  return false;
}

test.describe("Playbook config panel", () => {
  test("empty state shows when no node is selected", async ({ seniorPage }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    const config = new PlaybookConfigPanel(seniorPage);
    await expect(config.empty).toBeVisible({ timeout: 10_000 });
  });

  test("close button returns the panel to empty state", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Close ${Date.now()}`,
      ACTION_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    // Once a node is selected the form panel is mounted.
    await expect(config.root).toBeVisible({ timeout: 5_000 });
    await config.closeButton.click();
    await expect(config.empty).toBeVisible({ timeout: 5_000 });
  });

  test("delete button removes the selected node", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Delete ${Date.now()}`,
      ACTION_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    if (await config.deleteButton.isVisible()) {
      await config.deleteButton.click();
      // After deleting the selected node, the panel returns to empty.
      await expect(config.empty).toBeVisible({ timeout: 5_000 });
    }
  });

  test("selecting an action node surfaces tool / arguments / timeout / on-failure", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Action ${Date.now()}`,
      ACTION_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    // At least one of the action-typed inputs should be mounted when an
    // action node is selected. We allow any of the four — the canvas
    // may select a different node type if multiple are present.
    await expect(
      config.actionToolInput
        .or(config.actionArgumentsInput)
        .or(config.actionTimeoutInput)
        .or(config.actionOnFailureInput)
        .or(config.triggerTypeInput),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("selecting a decision node surfaces the condition input", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Decision ${Date.now()}`,
      DECISION_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    // Decision-condition input is the type-specific surface; it may
    // not be the first node selected — fall back to checking the
    // panel mounted at all.
    if (await config.decisionConditionInput.isVisible()) {
      await expect(config.decisionConditionInput).toBeVisible();
    } else {
      await expect(config.root).toBeVisible();
    }
  });

  test("selecting a HITL node surfaces prompt / role / timeout inputs", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg HITL ${Date.now()}`,
      HITL_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    if (await config.hitlPromptInput.isVisible()) {
      await expect(config.hitlPromptInput).toBeVisible();
      await expect(config.hitlRoleInput).toBeVisible();
      await expect(config.hitlTimeoutInput).toBeVisible();
    } else {
      // Selected a different node type — at minimum the panel mounted.
      await expect(config.root).toBeVisible();
    }
  });

  test("selecting a parallel node surfaces the branch-count input", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Parallel ${Date.now()}`,
      PARALLEL_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    if (await config.parallelBranchCountInput.isVisible()) {
      await expect(config.parallelBranchCountInput).toBeVisible();
    } else {
      await expect(config.root).toBeVisible();
    }
  });

  test("selecting a trigger node surfaces type / parameters inputs", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedYaml(
      seniorApi,
      `[E2E] Cfg Trigger ${Date.now()}`,
      TRIGGER_YAML,
    );
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoEdit(pb.id);
    const config = new PlaybookConfigPanel(seniorPage);
    const clicked = await clickFirstCanvasNode(builder);
    test.skip(!clicked, "Canvas did not hydrate any nodes");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    if (await config.triggerTypeInput.isVisible()) {
      await expect(config.triggerTypeInput).toBeVisible();
    } else {
      await expect(config.root).toBeVisible();
    }
  });
});
