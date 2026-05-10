/**
 * Knowledge surface POM — combined search + document list +
 * ingest-modal helpers. The KnowledgePage component is the wrapper
 * that hosts both KnowledgeSearch and KnowledgeDocumentList.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

class KnowledgeSearch {
  readonly page: Page;
  readonly root: Locator;
  readonly form: Locator;
  readonly input: Locator;
  readonly submitButton: Locator;
  readonly clearButton: Locator;
  readonly filtersToggle: Locator;
  readonly filters: Locator;
  readonly results: Locator;
  readonly empty: Locator;
  readonly error: Locator;
  readonly errorDismiss: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("knowledge-search");
    this.form = page.getByTestId("knowledge-search-form");
    this.input = page.getByTestId("knowledge-search-input");
    this.submitButton = page.getByTestId("knowledge-search-submit-button");
    this.clearButton = page.getByTestId("knowledge-search-clear-button");
    this.filtersToggle = page.getByTestId("knowledge-search-filters-toggle");
    this.filters = page.getByTestId("knowledge-search-filters");
    this.results = page.getByTestId("knowledge-search-results");
    this.empty = page.getByTestId("knowledge-search-empty");
    this.error = page.getByTestId("knowledge-search-error");
    this.errorDismiss = page.getByTestId(
      "knowledge-search-error-dismiss-button",
    );
  }

  filterTab(value: string): Locator {
    // ``-filter-all`` was committed; sibling tabs follow the same
    // pattern (e.g. ``-filter-runbook``, ``-filter-threat-profile``).
    return this.page.getByTestId(`knowledge-search-filter-${value}`);
  }

  async submit(query: string): Promise<void> {
    await this.input.fill(query);
    await this.submitButton.click();
  }

  async clear(): Promise<void> {
    await this.clearButton.click();
  }
}

class KnowledgeIngestModal {
  readonly page: Page;
  readonly dialog: Locator;
  readonly form: Locator;
  readonly titleInput: Locator;
  readonly contentInput: Locator;
  readonly sourceInput: Locator;
  readonly fileInput: Locator;
  readonly submitButton: Locator;
  readonly cancelButton: Locator;
  readonly closeButton: Locator;
  readonly error: Locator;
  readonly success: Locator;

  constructor(page: Page) {
    this.page = page;
    this.dialog = page.getByTestId("knowledge-ingest-dialog");
    this.form = page.getByTestId("knowledge-ingest-form");
    this.titleInput = page.getByTestId("knowledge-ingest-title-input");
    this.contentInput = page.getByTestId("knowledge-ingest-content-input");
    this.sourceInput = page.getByTestId("knowledge-ingest-source-input");
    this.fileInput = page.getByTestId("knowledge-ingest-file-input");
    this.submitButton = page.getByTestId("knowledge-ingest-submit-button");
    this.cancelButton = page.getByTestId("knowledge-ingest-cancel-button");
    this.closeButton = page.getByTestId("knowledge-ingest-close-button");
    this.error = page.getByTestId("knowledge-ingest-error");
    this.success = page.getByTestId("knowledge-ingest-success");
  }

  async fill(args: {
    title: string;
    content: string;
    source?: string;
  }): Promise<void> {
    await this.titleInput.fill(args.title);
    await this.contentInput.fill(args.content);
    if (args.source) await this.sourceInput.selectOption(args.source);
  }

  async submit(): Promise<void> {
    await this.submitButton.click();
  }
}

class KnowledgeDocumentList {
  readonly page: Page;
  readonly root: Locator;
  readonly items: Locator;
  readonly loading: Locator;
  readonly empty: Locator;
  readonly pagination: Locator;
  readonly nextButton: Locator;
  readonly prevButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("knowledge-list");
    this.items = page.getByTestId("knowledge-list-items");
    this.loading = page.getByTestId("knowledge-list-loading");
    this.empty = page.getByTestId("knowledge-list-empty");
    this.pagination = page.getByTestId("knowledge-list-pagination");
    this.nextButton = page.getByTestId("knowledge-list-next-button");
    this.prevButton = page.getByTestId("knowledge-list-prev-button");
  }

  /** A specific knowledge document row by id. */
  doc(id: string): Locator {
    return this.page.getByTestId(`knowledge-doc-${id}`);
  }

  /** Delete button on a specific doc. */
  deleteButton(id: string): Locator {
    return this.page.getByTestId(`knowledge-doc-${id}-delete-button`);
  }
}

export class KnowledgePage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly ingestOpenButton: Locator;
  readonly search: KnowledgeSearch;
  readonly ingest: KnowledgeIngestModal;
  readonly list: KnowledgeDocumentList;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("knowledge");
    this.ingestOpenButton = page.getByTestId("knowledge-ingest-open-button");
    this.search = new KnowledgeSearch(page);
    this.ingest = new KnowledgeIngestModal(page);
    this.list = new KnowledgeDocumentList(page);
  }

  async goto(): Promise<void> {
    await this.page.goto("/knowledge");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }
}
