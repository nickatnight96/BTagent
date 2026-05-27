/**
 * POMs for the NightWing vertical slices — Hunt Package (UC-1.3),
 * Correlation Workbench (UC-1.2), and the Audit Ledger.
 *
 * Each page exposes the page-root testid plus the input/result testids
 * the components already render, so specs assert on stable hooks rather
 * than copy. Navigation goes through the Sidebar POM (see the note in
 * ``sidebar.ts`` about not using raw ``page.goto`` from a test).
 */
import type { Locator, Page } from "@playwright/test";
import { Header } from "./header";
import { Sidebar } from "./sidebar";

export class HuntPackagePage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly input: Locator;
  readonly result: Locator;
  readonly generateButton: Locator;
  readonly sampleButton: Locator;
  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("hunt-package");
    this.input = page.getByTestId("hunt-package-input");
    this.result = page.getByTestId("hunt-package-result");
    this.generateButton = page.getByRole("button", {
      name: /generate hunt package/i,
    });
    this.sampleButton = page.getByRole("button", {
      name: /use sample advisory/i,
    });
    this.error = page.getByRole("alert");
  }

  async goto(): Promise<void> {
    await this.sidebar.goToHunts();
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }
}

export class CorrelationPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly input: Locator;
  readonly result: Locator;
  readonly correlateButton: Locator;
  readonly sampleButton: Locator;
  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("correlation");
    this.input = page.getByTestId("correlation-input");
    this.result = page.getByTestId("correlation-result");
    this.correlateButton = page.getByRole("button", { name: /^correlate$/i });
    this.sampleButton = page.getByRole("button", { name: /use sample entity/i });
    this.error = page.getByRole("alert");
  }

  async goto(): Promise<void> {
    await this.sidebar.goToCorrelate();
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }
}

export class AuditLedgerPage {
  readonly page: Page;
  readonly header: Header;
  readonly sidebar: Sidebar;
  readonly root: Locator;
  readonly table: Locator;
  readonly error: Locator;

  constructor(page: Page) {
    this.page = page;
    this.header = new Header(page);
    this.sidebar = new Sidebar(page);
    this.root = page.getByTestId("audit-ledger");
    this.table = page.getByTestId("audit-table");
    this.error = page.getByRole("alert");
  }

  async goto(): Promise<void> {
    await this.sidebar.goToAudit();
    await this.root.waitFor({ state: "visible", timeout: 10_000 });
  }
}
