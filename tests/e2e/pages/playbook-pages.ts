/**
 * Playbook surface POMs — list / builder / config / yaml / execution.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export class PlaybookListPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly searchInput: Locator;
  readonly newButton: Locator;
  readonly grid: Locator;
  readonly empty: Locator;
  readonly emptyNewButton: Locator;
  readonly loading: Locator;
  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("playbook-list");
    this.searchInput = page.getByTestId("playbook-list-search-input");
    this.newButton = page.getByTestId("playbook-list-new-button");
    this.grid = page.getByTestId("playbook-list-grid");
    this.empty = page.getByTestId("playbook-list-empty");
    this.emptyNewButton = page.getByTestId("playbook-list-empty-new-button");
    this.loading = page.getByTestId("playbook-list-loading");
    this.error = page.getByTestId("playbook-list-error");
  }

  async goto(): Promise<void> {
    await this.page.goto("/playbooks");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  /** Per-playbook card. */
  card(id: string): Locator {
    return this.page.getByTestId(`playbook-list-item-${id}`);
  }

  cardEditButton(id: string): Locator {
    return this.page.getByTestId(`playbook-list-item-${id}-edit-button`);
  }

  cardDeleteButton(id: string): Locator {
    return this.page.getByTestId(`playbook-list-item-${id}-delete-button`);
  }

  cardExecuteButton(id: string): Locator {
    return this.page.getByTestId(`playbook-list-item-${id}-execute-button`);
  }
}

export class PlaybookBuilderPage {
  readonly page: Page;
  readonly root: Locator;
  readonly canvas: Locator;
  readonly toolbar: Locator;
  readonly title: Locator;
  readonly backButton: Locator;
  readonly mobileBackButton: Locator;
  readonly mobileWarning: Locator;
  readonly validateButton: Locator;
  readonly importYamlButton: Locator;
  readonly exportYamlButton: Locator;
  readonly yamlToggle: Locator;
  readonly saveButton: Locator;
  readonly errorDismissButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("playbook-builder");
    this.canvas = page.getByTestId("playbook-builder-canvas");
    this.toolbar = page.getByTestId("playbook-builder-toolbar");
    this.title = page.getByTestId("playbook-builder-title");
    this.backButton = page.getByTestId("playbook-builder-back-button");
    this.mobileBackButton = page.getByTestId(
      "playbook-builder-mobile-back-button",
    );
    this.mobileWarning = page.getByTestId("playbook-builder-mobile-warning");
    this.validateButton = page.getByTestId("playbook-builder-validate-button");
    this.importYamlButton = page.getByTestId(
      "playbook-builder-import-yaml-button",
    );
    this.exportYamlButton = page.getByTestId(
      "playbook-builder-export-yaml-button",
    );
    this.yamlToggle = page.getByTestId("playbook-builder-yaml-toggle");
    this.saveButton = page.getByTestId("playbook-builder-save-button");
    this.errorDismissButton = page.getByTestId(
      "playbook-builder-error-dismiss-button",
    );
  }

  async gotoNew(): Promise<void> {
    await this.page.goto("/playbooks/builder");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  async gotoEdit(id: string): Promise<void> {
    await this.page.goto(`/playbooks/builder/${id}`);
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }
}

export class PlaybookConfigPanel {
  readonly page: Page;
  readonly root: Locator;
  readonly empty: Locator;
  readonly closeButton: Locator;
  readonly deleteButton: Locator;
  readonly nodeIdInput: Locator;
  readonly labelInput: Locator;
  readonly actionToolInput: Locator;
  readonly actionArgumentsInput: Locator;
  readonly actionTimeoutInput: Locator;
  readonly actionOnFailureInput: Locator;
  readonly decisionConditionInput: Locator;
  readonly hitlPromptInput: Locator;
  readonly hitlRoleInput: Locator;
  readonly hitlTimeoutInput: Locator;
  readonly parallelBranchCountInput: Locator;
  readonly triggerTypeInput: Locator;
  readonly triggerParametersInput: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("playbook-config");
    this.empty = page.getByTestId("playbook-config-empty");
    this.closeButton = page.getByTestId("playbook-config-close-button");
    this.deleteButton = page.getByTestId("playbook-config-delete-button");
    this.nodeIdInput = page.getByTestId("playbook-config-node-id-input");
    this.labelInput = page.getByTestId("playbook-config-label-input");
    this.actionToolInput = page.getByTestId(
      "playbook-config-action-tool-input",
    );
    this.actionArgumentsInput = page.getByTestId(
      "playbook-config-action-arguments-input",
    );
    this.actionTimeoutInput = page.getByTestId(
      "playbook-config-action-timeout-input",
    );
    this.actionOnFailureInput = page.getByTestId(
      "playbook-config-action-on-failure-input",
    );
    this.decisionConditionInput = page.getByTestId(
      "playbook-config-decision-condition-input",
    );
    this.hitlPromptInput = page.getByTestId(
      "playbook-config-hitl-prompt-input",
    );
    this.hitlRoleInput = page.getByTestId("playbook-config-hitl-role-input");
    this.hitlTimeoutInput = page.getByTestId(
      "playbook-config-hitl-timeout-input",
    );
    this.parallelBranchCountInput = page.getByTestId(
      "playbook-config-parallel-branch-count-input",
    );
    this.triggerTypeInput = page.getByTestId(
      "playbook-config-trigger-type-input",
    );
    this.triggerParametersInput = page.getByTestId(
      "playbook-config-trigger-parameters-input",
    );
  }
}

export class PlaybookYamlEditor {
  readonly page: Page;
  readonly root: Locator;
  readonly editor: Locator;
  readonly copyButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("playbook-yaml");
    this.editor = page.getByTestId("playbook-yaml-editor");
    this.copyButton = page.getByTestId("playbook-yaml-copy-button");
  }
}

export class PlaybookExecutionPage {
  readonly page: Page;
  readonly root: Locator;
  readonly title: Locator;
  readonly status: Locator;
  readonly backButton: Locator;
  readonly startButton: Locator;
  readonly canvas: Locator;
  readonly timeline: Locator;
  readonly stepDetail: Locator;
  readonly stepDetailId: Locator;
  readonly stepDetailStatus: Locator;
  readonly stepDetailStarted: Locator;
  readonly stepDetailCompleted: Locator;
  readonly stepDetailError: Locator;
  readonly stepDetailOutput: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("playbook-execution");
    this.title = page.getByTestId("playbook-execution-title");
    this.status = page.getByTestId("playbook-execution-status");
    this.backButton = page.getByTestId("playbook-execution-back-button");
    this.startButton = page.getByTestId("playbook-execution-start-button");
    this.canvas = page.getByTestId("playbook-execution-canvas");
    this.timeline = page.getByTestId("playbook-execution-timeline");
    this.stepDetail = page.getByTestId("playbook-execution-step-detail");
    this.stepDetailId = page.getByTestId("playbook-execution-step-detail-id");
    this.stepDetailStatus = page.getByTestId(
      "playbook-execution-step-detail-status",
    );
    this.stepDetailStarted = page.getByTestId(
      "playbook-execution-step-detail-started",
    );
    this.stepDetailCompleted = page.getByTestId(
      "playbook-execution-step-detail-completed",
    );
    this.stepDetailError = page.getByTestId(
      "playbook-execution-step-detail-error",
    );
    this.stepDetailOutput = page.getByTestId(
      "playbook-execution-step-detail-output",
    );
  }

  async goto(playbookId: string): Promise<void> {
    await this.page.goto(`/playbooks/${playbookId}/execute`);
    await this.root.waitFor({ state: "visible", timeout: 15_000 });
    // The execution view embeds a ReactFlow canvas; the start-button
    // and the timeline panel both depend on the canvas finishing its
    // first hydration tick. Without this wait, ``startButton.click()``
    // can race the canvas mount and the click never registers — which
    // surfaces downstream as a missing timeline / step-detail
    // assertion. 15s allows for the worst-case CI cold-start.
    await this.canvas.waitFor({ state: "visible", timeout: 15_000 });
  }

  /** Per-timeline-step button. */
  timelineStep(stepId: string): Locator {
    return this.page.getByTestId(`playbook-execution-step-${stepId}`);
  }
}
