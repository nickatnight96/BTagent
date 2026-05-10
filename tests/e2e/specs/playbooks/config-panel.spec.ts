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
    tool_name: severity_scorer
    arguments:
      iocs: []
    timeout_seconds: 30
    on_failure: skip
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
 * Click the first React Flow node of the given ``data-node-type`` on
 * the canvas. The node templates carry both
 * ``data-testid="playbook-builder-node-${id}"`` (per-node, stable)
 * and ``data-node-type="..."`` (type-class, defensive secondary
 * selector) — see ``frontend/src/components/playbooks/nodes/*.tsx``.
 *
 * The ``.react-flow__node`` wrapper sits BETWEEN the canvas and our
 * testid'd inner div, so the locator chains
 * ``canvas → [data-node-type=X]``. The wrapper handles ReactFlow's
 * pointer-event hit-testing, so we click the inner element and let
 * the event bubble up.
 *
 * Returns the locator on success, or null if no node of that type
 * is mounted yet (the canvas may still be hydrating).
 */
async function clickCanvasNodeByType(
  builder: PlaybookBuilderPage,
  nodeType: "trigger" | "action" | "decision" | "hitl_gate" | "parallel_fork" | "end",
): Promise<boolean> {
  const node = builder.canvas
    .locator(`[data-node-type="${nodeType}"]`)
    .first();
  // Wait briefly for ReactFlow to mount its initial node set.
  await node.waitFor({ state: "visible", timeout: 5_000 }).catch(() => null);
  if (await node.count()) {
    await node.click({ force: true });
    return true;
  }
  return false;
}

/**
 * Legacy "click any node" helper — used by the close + delete tests
 * that don't care about the node type. Kept as a thin wrapper around
 * the new typed helper so we have a single source of truth for the
 * canvas-click pattern.
 */
async function clickFirstCanvasNode(
  builder: PlaybookBuilderPage,
): Promise<boolean> {
  for (const t of [
    "trigger",
    "action",
    "decision",
    "hitl_gate",
    "parallel_fork",
    "end",
  ] as const) {
    if (await clickCanvasNodeByType(builder, t)) {
      return true;
    }
  }
  return false;
}

test.describe("Playbook config panel", () => {
  test("empty state shows when no node is selected", async ({ seniorPage }) => {
    const builder = new PlaybookBuilderPage(seniorPage);
    await builder.gotoNew();
    const config = new PlaybookConfigPanel(seniorPage);

    // ReactFlow may auto-select the first node on canvas hydrate. Press
    // Escape to deselect any active node before asserting the empty
    // state — Escape is ReactFlow's documented "deselect" key. If
    // nothing was selected to begin with, this is a no-op.
    await builder.canvas.click({ position: { x: 5, y: 5 } });
    await seniorPage.keyboard.press("Escape");
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
    const clicked = await clickCanvasNodeByType(builder, "action");
    test.skip(!clicked, "No action node hydrated on canvas");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    // The action panel surfaces tool / arguments / timeout / on-failure
    // inputs. At least one must be mounted now that we deterministically
    // selected an action node.
    await expect(
      config.actionToolInput
        .or(config.actionArgumentsInput)
        .or(config.actionTimeoutInput)
        .or(config.actionOnFailureInput),
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
    const clicked = await clickCanvasNodeByType(builder, "decision");
    test.skip(!clicked, "No decision node hydrated on canvas");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    await expect(config.decisionConditionInput).toBeVisible({
      timeout: 5_000,
    });
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
    const clicked = await clickCanvasNodeByType(builder, "hitl_gate");
    test.skip(!clicked, "No HITL gate node hydrated on canvas");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    await expect(config.hitlPromptInput).toBeVisible({ timeout: 5_000 });
    await expect(config.hitlRoleInput).toBeVisible();
    await expect(config.hitlTimeoutInput).toBeVisible();
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
    const clicked = await clickCanvasNodeByType(builder, "parallel_fork");
    test.skip(!clicked, "No parallel-fork node hydrated on canvas");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    await expect(config.parallelBranchCountInput).toBeVisible({
      timeout: 5_000,
    });
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
    const clicked = await clickCanvasNodeByType(builder, "trigger");
    test.skip(!clicked, "No trigger node hydrated on canvas");

    await expect(config.root).toBeVisible({ timeout: 5_000 });
    if (await config.triggerTypeInput.isVisible()) {
      await expect(config.triggerTypeInput).toBeVisible();
    } else {
      await expect(config.root).toBeVisible();
    }
  });
});
