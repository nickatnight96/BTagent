/**
 * NewInvestigationModal POM — opened from the InvestigationList "+" button.
 */
import type { Locator, Page } from "@playwright/test";

export class NewInvestigationModal {
  readonly page: Page;
  readonly dialog: Locator;
  readonly form: Locator;
  readonly titleInput: Locator;
  readonly descriptionInput: Locator;
  readonly severityInput: Locator;
  readonly tlpInput: Locator;
  readonly templateInput: Locator;
  readonly errorMessage: Locator;
  readonly cancelButton: Locator;
  readonly submitButton: Locator;

  constructor(page: Page) {
    this.page = page;
    this.dialog = page.getByTestId("new-investigation-dialog");
    this.form = page.getByTestId("new-investigation-form");
    this.titleInput = page.getByTestId("new-investigation-title-input");
    this.descriptionInput = page.getByTestId(
      "new-investigation-description-input",
    );
    this.severityInput = page.getByTestId("new-investigation-severity-input");
    this.tlpInput = page.getByTestId("new-investigation-tlp-input");
    this.templateInput = page.getByTestId("new-investigation-template-input");
    this.errorMessage = page.getByTestId("new-investigation-error");
    this.cancelButton = page.getByTestId("new-investigation-cancel-button");
    this.submitButton = page.getByTestId("new-investigation-submit-button");
  }

  async fill(args: {
    title: string;
    description?: string;
    severity?: string;
    tlpLevel?: string;
    template?: string;
  }): Promise<void> {
    await this.titleInput.fill(args.title);
    if (args.description) await this.descriptionInput.fill(args.description);
    if (args.severity) await this.severityInput.selectOption(args.severity);
    if (args.tlpLevel) await this.tlpInput.selectOption(args.tlpLevel);
    if (args.template) await this.templateInput.selectOption(args.template);
  }

  async submit(): Promise<void> {
    await this.submitButton.click();
  }

  async cancel(): Promise<void> {
    await this.cancelButton.click();
  }
}
