/**
 * Sidebar POM — primary nav. ``goTo`` is the canonical way for tests
 * to switch surfaces; never use raw ``page.goto`` from a test, since
 * that bypasses the auth-protected route guard and hides nav-bug
 * regressions.
 */
import type { Locator, Page } from "@playwright/test";

export class Sidebar {
  readonly page: Page;
  readonly root: Locator;
  readonly brand: Locator;
  readonly punchlistLink: Locator;
  readonly investigationsLink: Locator;
  readonly iocsLink: Locator;
  readonly mitreLink: Locator;
  readonly knowledgeLink: Locator;
  readonly huntsLink: Locator;
  readonly correlateLink: Locator;
  readonly playbooksLink: Locator;
  readonly auditLink: Locator;
  readonly settingsLink: Locator;
  readonly collapseToggle: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("sidebar");
    this.brand = page.getByTestId("sidebar-brand");
    this.punchlistLink = page.getByTestId("nav-punchlist-link");
    this.investigationsLink = page.getByTestId("nav-investigations-link");
    this.iocsLink = page.getByTestId("nav-iocs-link");
    this.mitreLink = page.getByTestId("nav-mitre-link");
    this.knowledgeLink = page.getByTestId("nav-knowledge-link");
    this.huntsLink = page.getByTestId("nav-hunts-link");
    this.correlateLink = page.getByTestId("nav-correlate-link");
    this.playbooksLink = page.getByTestId("nav-playbooks-link");
    this.auditLink = page.getByTestId("nav-audit-link");
    this.settingsLink = page.getByTestId("nav-settings-link");
    this.collapseToggle = page.getByTestId("sidebar-collapse-toggle");
  }

  async goToInvestigations(): Promise<void> {
    await this.investigationsLink.click();
    await this.page.waitForURL("**/", { timeout: 5_000 });
  }

  async goToIOCs(): Promise<void> {
    await this.iocsLink.click();
    await this.page.waitForURL("**/iocs", { timeout: 5_000 });
  }

  async goToMitre(): Promise<void> {
    await this.mitreLink.click();
    await this.page.waitForURL("**/mitre", { timeout: 5_000 });
  }

  async goToKnowledge(): Promise<void> {
    await this.knowledgeLink.click();
    await this.page.waitForURL("**/knowledge", { timeout: 5_000 });
  }

  async goToHunts(): Promise<void> {
    await this.huntsLink.click();
    await this.page.waitForURL("**/hunts", { timeout: 5_000 });
  }

  async goToCorrelate(): Promise<void> {
    await this.correlateLink.click();
    await this.page.waitForURL("**/correlate", { timeout: 5_000 });
  }

  async goToPlaybooks(): Promise<void> {
    await this.playbooksLink.click();
    await this.page.waitForURL("**/playbooks", { timeout: 5_000 });
  }

  async goToAudit(): Promise<void> {
    await this.auditLink.click();
    await this.page.waitForURL("**/audit", { timeout: 5_000 });
  }

  async toggleCollapse(): Promise<void> {
    await this.collapseToggle.click();
  }
}
