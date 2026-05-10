/**
 * Header POM — top bar with user info and logout.
 */
import type { Locator, Page } from "@playwright/test";

export class Header {
  readonly page: Page;
  readonly root: Locator;
  readonly title: Locator;
  readonly menuToggle: Locator;
  readonly userBlock: Locator;
  readonly userName: Locator;
  readonly userRole: Locator;
  readonly logoutButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.root = page.getByTestId("header");
    this.title = page.getByTestId("header-title");
    this.menuToggle = page.getByTestId("header-menu-toggle");
    this.userBlock = page.getByTestId("header-user");
    this.userName = page.getByTestId("header-user-name");
    this.userRole = page.getByTestId("header-user-role");
    this.logoutButton = page.getByTestId("header-logout-button");
  }

  async logout(): Promise<void> {
    await this.logoutButton.click();
    await this.page.waitForURL(/\/login(\?|\#|$)/, { timeout: 5_000 });
  }
}
