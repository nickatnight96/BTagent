/**
 * InvestigationWorkspace POM — the ``/investigations/:id`` page,
 * with embedded sub-POMs for the chat / event-stream / cost-badge
 * panels that live inside it.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

class AgentChat {
  readonly page: Page;
  readonly root: Locator;
  readonly form: Locator;
  readonly input: Locator;
  readonly sendButton: Locator;
  readonly messageList: Locator;
  readonly loading: Locator;
  readonly empty: Locator;
  readonly thinking: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("agent-chat");
    this.form = page.getByTestId("agent-chat-form");
    this.input = page.getByTestId("agent-chat-input");
    this.sendButton = page.getByTestId("agent-chat-send-button");
    this.messageList = page.getByTestId("agent-chat-message-list");
    this.loading = page.getByTestId("agent-chat-loading");
    this.empty = page.getByTestId("agent-chat-empty");
    this.thinking = page.getByTestId("agent-chat-thinking");
  }

  /** One message row by message id. */
  message(id: string): Locator {
    return this.page.getByTestId(`agent-chat-message-${id}`);
  }

  async send(text: string): Promise<void> {
    await this.input.fill(text);
    await this.sendButton.click();
  }
}

class EventStream {
  readonly page: Page;
  readonly root: Locator;
  readonly count: Locator;
  readonly list: Locator;
  readonly empty: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("event-stream");
    this.count = page.getByTestId("event-stream-count");
    this.list = page.getByTestId("event-stream-list");
    this.empty = page.getByTestId("event-stream-empty");
  }

  /** One event row by event id (or templated index). */
  event(id: string): Locator {
    return this.page.getByTestId(`event-stream-item-${id}`);
  }
}

class CostBadge {
  readonly page: Page;
  readonly root: Locator;
  readonly value: Locator;
  readonly tooltip: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("cost-badge");
    this.value = page.getByTestId("cost-badge-value");
    this.tooltip = page.getByTestId("cost-badge-tooltip");
  }
}

export class InvestigationWorkspacePage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly title: Locator;
  readonly loading: Locator;
  readonly backButton: Locator;
  readonly pauseButton: Locator;
  readonly resumeButton: Locator;
  readonly stopButton: Locator;
  readonly tabs: Locator;
  readonly chat: AgentChat;
  readonly events: EventStream;
  readonly cost: CostBadge;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("investigation-workspace");
    this.title = page.getByTestId("investigation-workspace-title");
    this.loading = page.getByTestId("investigation-workspace-loading");
    this.backButton = page.getByTestId("investigation-workspace-back-button");
    this.pauseButton = page.getByTestId("investigation-workspace-pause-button");
    this.resumeButton = page.getByTestId(
      "investigation-workspace-resume-button",
    );
    this.stopButton = page.getByTestId("investigation-workspace-stop-button");
    this.tabs = page.getByTestId("investigation-workspace-tabs");
    this.chat = new AgentChat(page);
    this.events = new EventStream(page);
    this.cost = new CostBadge(page);
  }

  async gotoById(id: string): Promise<void> {
    await this.page.goto(`/investigations/${id}`);
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  /** Tab button — id is e.g. "overview", "iocs", "mitre", "evidence". */
  tab(id: string): Locator {
    return this.page.getByTestId(`investigation-workspace-tab-${id}`);
  }

  async switchTab(id: string): Promise<void> {
    await this.tab(id).click();
  }
}
