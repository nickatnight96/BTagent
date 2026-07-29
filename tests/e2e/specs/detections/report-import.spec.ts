/**
 * CTI report-text import E2E spec (#113 back half, #497).
 *
 * The unit/route layers cover extraction and the panel in isolation; this
 * spec drives the real stack: paste unstructured (defanged) CTI prose on the
 * Detection Proposals page, and verify proposals materialize in the review
 * list below — the full browser → API → extraction → persistence → re-fetch
 * loop.
 *
 * Per-run unique IDs: the pasted report carries a per-invocation runTag in
 * its C2 domain so parallel shards never collide on proposal upserts
 * (extraction is deterministic — same text upserts, never duplicates).
 */
import { test, expect } from "../../fixtures/auth";

test.describe("Detection Proposals — report-text import", () => {
  test("pasted defanged report yields proposals in the review list", async ({
    analystPage,
  }) => {
    const runTag = `e2e${Date.now()}`;
    const domain = `c2-${runTag}.example-mal.net`;
    const report =
      `Incident write-up ${runTag}: spearphishing attachment delivered a ` +
      `dropper which spawned powershell with an encoded command beaconing ` +
      `to hxxps://${domain}/api every 60 seconds.`;

    await analystPage.goto("/detection-proposals");
    await analystPage
      .getByTestId("import-bundle-panel")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage.getByTestId("import-mode-report").click();
    await analystPage.getByTestId("import-bundle-input").fill(report);
    await analystPage.getByTestId("import-report-name").fill(`E2E advisory ${runTag}`);
    await analystPage.getByTestId("import-bundle-submit").click();

    // The result banner confirms the server round-trip (extraction + persist).
    const result = analystPage.getByTestId("import-bundle-result");
    await result.waitFor({ state: "visible", timeout: 15_000 });
    await expect(result).toContainText(/proposals? generated/);
    await expect(analystPage.getByTestId("import-bundle-persisted")).toContainText(/new/);

    // The refreshed review list carries a proposal derived from our unique
    // domain — proving persistence, not just the transient response.
    await analystPage.getByTestId("proposals-refresh").click();
    await expect(
      analystPage.getByText(domain, { exact: false }).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("prose without IOCs surfaces the server's 422 verbatim", async ({
    analystPage,
  }) => {
    await analystPage.goto("/detection-proposals");
    await analystPage
      .getByTestId("import-bundle-panel")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage.getByTestId("import-mode-report").click();
    await analystPage
      .getByTestId("import-bundle-input")
      .fill("The quarterly threat landscape remained calm with no notable activity.");
    await analystPage.getByTestId("import-bundle-submit").click();

    const error = analystPage.getByTestId("import-bundle-error");
    await error.waitFor({ state: "visible", timeout: 15_000 });
    await expect(error).toContainText(/No supported IOCs/);
  });

  test("bundle mode is unaffected by the toggle (regression guard)", async ({
    analystPage,
  }) => {
    await analystPage.goto("/detection-proposals");
    await analystPage
      .getByTestId("import-bundle-panel")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to report mode and back — bundle mode must still JSON-validate.
    await analystPage.getByTestId("import-mode-report").click();
    await analystPage.getByTestId("import-mode-bundle").click();
    await analystPage.getByTestId("import-bundle-input").fill("not json");
    await analystPage.getByTestId("import-bundle-submit").click();
    await expect(analystPage.getByTestId("import-bundle-error")).toContainText(
      /isn't valid JSON/,
    );
  });
});
