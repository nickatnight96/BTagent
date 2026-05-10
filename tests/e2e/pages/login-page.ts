/**
 * Login page object — wraps the ``/login`` form interactions.
 *
 * Page Object pattern keeps selectors out of test bodies, so a UI
 * refactor only touches the POM, not every test.
 */
import type { Locator, Page } from "@playwright/test";

export class LoginPage {
  readonly page: Page;
  readonly form: Locator;
  readonly usernameInput: Locator;
  readonly passwordInput: Locator;
  readonly passwordToggle: Locator;
  readonly submitButton: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;
    this.form = page.getByTestId("login-form");
    this.usernameInput = page.getByTestId("login-username-input");
    this.passwordInput = page.getByTestId("login-password-input");
    this.passwordToggle = page.getByTestId("login-password-toggle");
    this.submitButton = page.getByTestId("login-submit-button");
    this.errorMessage = page.getByTestId("login-error");
  }

  async goto(): Promise<void> {
    await this.page.goto("/login");
  }

  async login(username: string, password: string): Promise<void> {
    await this.usernameInput.fill(username);
    await this.passwordInput.fill(password);
    await this.submitButton.click();
  }

  async submitWaitingForRedirect(
    username: string,
    password: string,
  ): Promise<void> {
    await this.login(username, password);
    await this.page.waitForURL((url) => !url.pathname.endsWith("/login"), {
      timeout: 15_000,
    });
  }

  async expectError(): Promise<void> {
    await this.errorMessage.waitFor({ state: "visible", timeout: 5_000 });
  }
}
