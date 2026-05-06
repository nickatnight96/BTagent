/**
 * IOC notebook + detail / import / export modals POMs.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export class IOCDetailPanel {
  readonly page: Page;
  readonly root: Locator;
  readonly backdrop: Locator;
  readonly closeButton: Locator;
  readonly value: Locator;
  readonly investigationLink: Locator;
  readonly enrichButton: Locator;
  readonly relatedList: Locator;
  readonly virustotal: Locator;
  readonly shodan: Locator;
  readonly greynoise: Locator;
  readonly abuseipdb: Locator;
  readonly misp: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("ioc-detail");
    this.backdrop = page.getByTestId("ioc-detail-backdrop");
    this.closeButton = page.getByTestId("ioc-detail-close-button");
    this.value = page.getByTestId("ioc-detail-value");
    this.investigationLink = page.getByTestId("ioc-detail-investigation-link");
    this.enrichButton = page.getByTestId("ioc-detail-enrich-button");
    this.relatedList = page.getByTestId("ioc-detail-related-list");
    this.virustotal = page.getByTestId("ioc-detail-virustotal");
    this.shodan = page.getByTestId("ioc-detail-shodan");
    this.greynoise = page.getByTestId("ioc-detail-greynoise");
    this.abuseipdb = page.getByTestId("ioc-detail-abuseipdb");
    this.misp = page.getByTestId("ioc-detail-misp");
  }
}

export class IOCImportModal {
  readonly page: Page;
  readonly root: Locator;
  readonly investigationInput: Locator;
  readonly pasteInput: Locator;
  readonly preview: Locator;
  readonly previewTable: Locator;
  readonly result: Locator;
  readonly error: Locator;
  readonly cancelButton: Locator;
  readonly submitButton: Locator;
  readonly formatTabCsv: Locator;
  readonly formatTabStix: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("ioc-import");
    this.investigationInput = page.getByTestId(
      "ioc-import-investigation-input",
    );
    this.pasteInput = page.getByTestId("ioc-import-paste-input");
    this.preview = page.getByTestId("ioc-import-preview");
    this.previewTable = page.getByTestId("ioc-import-preview-table");
    this.result = page.getByTestId("ioc-import-result");
    this.error = page.getByTestId("ioc-import-error");
    this.cancelButton = page.getByTestId("ioc-import-cancel-button");
    this.submitButton = page.getByTestId("ioc-import-submit-button");
    this.formatTabCsv = page.getByTestId("ioc-import-format-tab-csv");
    this.formatTabStix = page.getByTestId("ioc-import-format-tab-stix");
  }
}

export class IOCExportDialog {
  readonly page: Page;
  readonly root: Locator;
  readonly investigationInput: Locator;
  readonly typeInput: Locator;
  readonly tlpInput: Locator;
  readonly confidenceInput: Locator;
  readonly tlpWarning: Locator;
  readonly cancelButton: Locator;
  readonly submitButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("ioc-export");
    this.investigationInput = page.getByTestId(
      "ioc-export-investigation-input",
    );
    this.typeInput = page.getByTestId("ioc-export-type-input");
    this.tlpInput = page.getByTestId("ioc-export-tlp-input");
    this.confidenceInput = page.getByTestId("ioc-export-confidence-input");
    this.tlpWarning = page.getByTestId("ioc-export-tlp-warning");
    this.cancelButton = page.getByTestId("ioc-export-cancel-button");
    this.submitButton = page.getByTestId("ioc-export-submit-button");
  }

  /** Format radio (e.g. ``stix``, ``csv``, ``misp``). */
  formatRadio(value: string): Locator {
    return this.page.getByTestId(`ioc-export-format-${value}-button`);
  }
}

export class IOCNotebookPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly searchInput: Locator;
  readonly typeFilter: Locator;
  readonly investigationFilter: Locator;
  readonly confidenceFilter: Locator;
  readonly filtersContainer: Locator;
  readonly refreshButton: Locator;
  readonly importButton: Locator;
  readonly exportButton: Locator;
  readonly bulkActions: Locator;
  readonly bulkEnrichButton: Locator;
  readonly bulkExportButton: Locator;
  readonly bulkClearButton: Locator;
  readonly selectAll: Locator;
  readonly table: Locator;
  readonly loading: Locator;
  readonly empty: Locator;
  readonly emptyImportButton: Locator;
  readonly error: Locator;
  readonly retryButton: Locator;
  readonly detailPanel: IOCDetailPanel;
  readonly importModal: IOCImportModal;
  readonly exportDialog: IOCExportDialog;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("ioc-notebook");
    this.searchInput = page.getByTestId("ioc-notebook-search-input");
    this.typeFilter = page.getByTestId("ioc-notebook-type-filter-input");
    this.investigationFilter = page.getByTestId(
      "ioc-notebook-investigation-filter-input",
    );
    this.confidenceFilter = page.getByTestId(
      "ioc-notebook-confidence-filter-input",
    );
    this.filtersContainer = page.getByTestId("ioc-notebook-filters");
    this.refreshButton = page.getByTestId("ioc-notebook-refresh-button");
    this.importButton = page.getByTestId("ioc-notebook-import-button");
    this.exportButton = page.getByTestId("ioc-notebook-export-button");
    this.bulkActions = page.getByTestId("ioc-notebook-bulk-actions");
    this.bulkEnrichButton = page.getByTestId(
      "ioc-notebook-bulk-enrich-button",
    );
    this.bulkExportButton = page.getByTestId(
      "ioc-notebook-bulk-export-button",
    );
    this.bulkClearButton = page.getByTestId("ioc-notebook-bulk-clear-button");
    this.selectAll = page.getByTestId("ioc-notebook-select-all-input");
    this.table = page.getByTestId("ioc-notebook-table");
    this.loading = page.getByTestId("ioc-notebook-loading");
    this.empty = page.getByTestId("ioc-notebook-empty");
    this.emptyImportButton = page.getByTestId(
      "ioc-notebook-empty-import-button",
    );
    this.error = page.getByTestId("ioc-notebook-error");
    this.retryButton = page.getByTestId("ioc-notebook-retry-button");
    this.detailPanel = new IOCDetailPanel(page);
    this.importModal = new IOCImportModal(page);
    this.exportDialog = new IOCExportDialog(page);
  }

  async goto(): Promise<void> {
    await this.page.goto("/iocs");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  /** Select-checkbox cell in the per-IOC row. */
  rowSelect(id: string): Locator {
    return this.page.getByTestId(`ioc-notebook-row-${id}-select`);
  }

  /** The row itself (clickable area opening the detail panel). */
  row(id: string): Locator {
    return this.page.getByTestId(`ioc-notebook-row-${id}`);
  }
}
