/**
 * Hunt Package slice (UC-1.3) — paste an advisory, generate a hunt
 * package, see derived techniques + per-backend queries render.
 *
 * Runs against the mock-mode backend (BTAGENT_MOCK_LLM /
 * BTAGENT_MOCK_CONNECTORS), so the generated package is deterministic.
 * The analyst persona holds ``hunt:run``.
 */
import { test, expect } from "../../fixtures/auth";
import { HuntPackagePage } from "../../pages/slice-pages";

test.describe("Hunt Package", () => {
  test("page renders for the analyst persona", async ({ analystPage }) => {
    const hunt = new HuntPackagePage(analystPage);
    await hunt.goto();
    await expect(hunt.root).toBeVisible();
    await expect(hunt.header.title).toHaveText("Hunt Package");
    await expect(hunt.generateButton).toBeDisabled(); // empty input
  });

  test("sample advisory populates the input and enables generate", async ({
    analystPage,
  }) => {
    const hunt = new HuntPackagePage(analystPage);
    await hunt.goto();
    await hunt.sampleButton.click();
    await expect(hunt.input).not.toHaveValue("");
    await expect(hunt.generateButton).toBeEnabled();
  });

  test("generating from the sample renders a hunt package end-to-end", async ({
    analystPage,
  }) => {
    const hunt = new HuntPackagePage(analystPage);
    await hunt.goto();
    await hunt.sampleButton.click();
    await hunt.generateButton.click();

    // Result block appears once the backend responds.
    await expect(hunt.result).toBeVisible({ timeout: 20_000 });
    await expect(hunt.result).toContainText("Derived ATT&CK techniques");
    await expect(hunt.result).toContainText("Pre-built hunt queries");
    // No error banner on the happy path.
    await expect(hunt.error).toHaveCount(0);
  });
});
