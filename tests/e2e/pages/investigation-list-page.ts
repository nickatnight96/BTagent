/**
 * Investigation list POM — the ``/`` PunchList view.
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export class InvestigationListPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly searchInput: Locator;
  readonly refreshButton: Locator;
  readonly newButton: Locator;
  readonly filters: Locator;
  readonly grid: Locator;
  readonly loading: Locator;
  readonly empty: Locator;
  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("investigation-list");
    this.searchInput = page.getByTestId("investigation-list-search-input");
    this.refreshButton = page.getByTestId("investigation-list-refresh-button");
    this.newButton = page.getByTestId("investigation-list-new-button");
    this.filters = page.getByTestId("investigation-list-filters");
    this.grid = page.getByTestId("investigation-list-grid");
    this.loading = page.getByTestId("investigation-list-loading");
    this.empty = page.getByTestId("investigation-list-empty");
    this.error = page.getByTestId("investigation-list-error");
  }

  async goto(): Promise<void> {
    await this.page.goto("/");
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }

  /** Locator for one investigation card by id. */
  cardFor(id: string): Locator {
    return this.page.getByTestId(`investigation-card-${id}`);
  }

  /** Filter tab by status. ``""`` selects "All". */
  filterTab(status: string): Locator {
    return this.page.getByTestId(
      `investigation-list-filter-${status || "all"}`,
    );
  }

  async filterByStatus(status: string): Promise<void> {
    await this.filterTab(status).click();
  }

  async search(query: string): Promise<void> {
    await this.searchInput.fill(query);
  }

  async openNewModal(): Promise<void> {
    await this.newButton.click();
  }

  async openInvestigation(id: string): Promise<void> {
    await this.cardFor(id).click();
    await this.page.waitForURL(`**/investigations/${id}`, { timeout: 5_000 });
  }
}
