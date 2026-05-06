/**
 * MITRE matrix POM + technique-detail modal POM.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export class TechniqueDetailModal {
  readonly page: Page;
  readonly root: Locator;
  readonly backdrop: Locator;
  readonly closeButton: Locator;
  readonly id: Locator;
  readonly name: Locator;
  readonly subtechniqueBadge: Locator;
  readonly subtechniques: Locator;
  readonly mitreLink: Locator;
  readonly exportButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("technique-detail");
    this.backdrop = page.getByTestId("technique-detail-backdrop");
    this.closeButton = page.getByTestId("technique-detail-close-button");
    this.id = page.getByTestId("technique-detail-id");
    this.name = page.getByTestId("technique-detail-name");
    this.subtechniqueBadge = page.getByTestId(
      "technique-detail-subtechnique-badge",
    );
    this.subtechniques = page.getByTestId("technique-detail-subtechniques");
    this.mitreLink = page.getByTestId("technique-detail-mitre-link");
    this.exportButton = page.getByTestId("technique-detail-export-button");
  }

  /** Tactic chip by name (slugified). */
  tacticChip(slug: string): Locator {
    return this.page.getByTestId(`technique-detail-tactic-${slug}`);
  }

  async close(): Promise<void> {
    await this.closeButton.click();
    await this.root.waitFor({ state: "hidden", timeout: 5_000 });
  }
}

export class MitreMatrixPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly grid: Locator;
  readonly loading: Locator;
  readonly empty: Locator;
  readonly error: Locator;
  readonly retryButton: Locator;
  readonly searchInput: Locator;
  readonly investigationFilterInput: Locator;
  readonly viewToggle: Locator;
  readonly viewToggleGlobal: Locator;
  readonly viewToggleInvestigation: Locator;
  readonly coverage: Locator;
  readonly coverageScore: Locator;
  readonly truncationNotice: Locator;
  readonly exportButton: Locator;
  readonly detailModal: TechniqueDetailModal;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("mitre-matrix");
    this.grid = page.getByTestId("mitre-matrix-grid");
    this.loading = page.getByTestId("mitre-matrix-loading");
    this.empty = page.getByTestId("mitre-matrix-empty");
    this.error = page.getByTestId("mitre-matrix-error");
    this.retryButton = page.getByTestId("mitre-matrix-retry-button");
    this.searchInput = page.getByTestId("mitre-matrix-search-input");
    this.investigationFilterInput = page.getByTestId(
      "mitre-matrix-investigation-filter-input",
    );
    this.viewToggle = page.getByTestId("mitre-matrix-view-toggle");
    this.viewToggleGlobal = page.getByTestId(
      "mitre-matrix-view-toggle-global",
    );
    this.viewToggleInvestigation = page.getByTestId(
      "mitre-matrix-view-toggle-investigation",
    );
    this.coverage = page.getByTestId("mitre-matrix-coverage");
    this.coverageScore = page.getByTestId("mitre-matrix-coverage-score");
    this.truncationNotice = page.getByTestId("mitre-matrix-truncation-notice");
    this.exportButton = page.getByTestId("mitre-matrix-export-button");
    this.detailModal = new TechniqueDetailModal(page);
  }

  async goto(): Promise<void> {
    await this.page.goto("/mitre");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  /** Tactic-column locator by slug (e.g. ``initial-access``). */
  tacticColumn(slug: string): Locator {
    return this.page.getByTestId(`mitre-tactic-column-${slug}`);
  }

  /** Single technique cell by id (e.g. ``T1078``). */
  techniqueCell(id: string): Locator {
    return this.page.getByTestId(`mitre-technique-cell-${id}`);
  }

  async openTechnique(id: string): Promise<TechniqueDetailModal> {
    await this.techniqueCell(id).click();
    await this.detailModal.root.waitFor({ state: "visible", timeout: 5_000 });
    return this.detailModal;
  }
}
