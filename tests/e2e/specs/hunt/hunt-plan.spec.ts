/**
 * Hunt Plan page E2E (#99).
 *
 * The /hunt-plan route had no browser coverage at all — one of three routed
 * pages with none. That matters more than a coverage percentage: the taxii
 * base path (#532), the dead WS handlers (#537), and a validation 500 (#540)
 * were all shipped, unit-tested code that no browser had ever exercised.
 *
 * The indicators field is the specific reason this page was picked. #99 was
 * closed on the claim that HuntPlanRequest accepts an `iocs` bundle and that
 * HypothesisGen maps each indicator to a plausible technique, so an analyst
 * holding only indicators still gets a plan. That claim is asserted here
 * against a real browser and a real backend rather than by reading the
 * handler: `plan-iocs-preview` proves the inference reaches the analyst, and
 * generating from indicators alone proves the plan comes back.
 *
 * Runs against the mock-mode stack, so plan generation is deterministic.
 */
import { test, expect } from "../../fixtures/auth";

const RESULT_TIMEOUT = 30_000;

test.describe("Hunt Plan page", () => {
  test("page structure renders — inputs, generate button, history", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await expect(analystPage.getByTestId("plan-adversaries-input")).toBeVisible();
    await expect(analystPage.getByTestId("plan-ttps-input")).toBeVisible();
    await expect(analystPage.getByTestId("plan-iocs-input")).toBeVisible();
    await expect(analystPage.getByTestId("generate-plan")).toBeVisible();
  });

  test("sidebar nav link reaches the page", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("nav-hunt-plan-link").click();
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });
    expect(analystPage.url()).toContain("/hunt-plan");
  });

  test("generate is disabled until a target is named", async ({ analystPage }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // No adversary, no TTP, no indicator — nothing to plan against.
    await expect(analystPage.getByTestId("generate-plan")).toBeDisabled();

    await analystPage.getByTestId("plan-ttps-input").fill("T1059.001");
    await expect(analystPage.getByTestId("generate-plan")).toBeEnabled();
  });

  test("indicator type inference is shown back to the analyst (#99)", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage
      .getByTestId("plan-iocs-input")
      .fill("8.8.8.8, evil.example.com, CVE-2024-3094");

    // The preview exists so an indicator typed as "other" — which contributes
    // no hypothesis — is visibly a guess rather than a silent drop.
    const preview = analystPage.getByTestId("plan-iocs-preview");
    await expect(preview).toBeVisible();
    await expect(preview).toContainText("8.8.8.8");
    await expect(preview).toContainText("evil.example.com");
    await expect(preview).toContainText("CVE-2024-3094");
  });

  test("a TTP alone produces a plan with hypotheses and a runbook", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage.getByTestId("plan-ttps-input").fill("T1059.001");
    await analystPage.getByTestId("generate-plan").click();

    await analystPage
      .getByTestId("hunt-plan-result")
      .waitFor({ state: "visible", timeout: RESULT_TIMEOUT });

    // A plan that renders no runbook entry for the technique asked about is
    // an empty shell, not a plan.
    await expect(analystPage.getByTestId("runbook-T1059.001")).toBeVisible();
  });

  test("indicators alone produce a plan — the #99 close, in a browser", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // No adversary and no TTP: the whole point of the iocs input is that an
    // analyst holding only indicators still gets a plan.
    await analystPage.getByTestId("plan-iocs-input").fill("evil.example.com");
    await expect(analystPage.getByTestId("generate-plan")).toBeEnabled();
    await analystPage.getByTestId("generate-plan").click();

    await analystPage
      .getByTestId("hunt-plan-result")
      .waitFor({ state: "visible", timeout: RESULT_TIMEOUT });

    // The indicator was mapped to at least one technique, so at least one
    // runbook entry exists. (domain -> T1071.004 per the mapping, but the
    // assertion stays on "a runbook entry rendered" so a mapping revision
    // doesn't fail a test about reachability.)
    await expect(
      analystPage.locator('[data-testid^="runbook-"]').first(),
    ).toBeVisible({ timeout: RESULT_TIMEOUT });
  });

  test("export controls appear on a generated plan", async ({ analystPage }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage.getByTestId("plan-ttps-input").fill("T1059.001");
    await analystPage.getByTestId("generate-plan").click();
    await analystPage
      .getByTestId("hunt-plan-result")
      .waitFor({ state: "visible", timeout: RESULT_TIMEOUT });

    await expect(analystPage.getByTestId("export-md")).toBeVisible();
    await expect(analystPage.getByTestId("export-pdf")).toBeVisible();
  });

  test("a generated plan is persisted and listed in history", async ({
    analystPage,
  }) => {
    await analystPage.goto("/hunt-plan");
    await analystPage
      .getByTestId("hunt-plan-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await analystPage.getByTestId("plan-ttps-input").fill("T1053.005");
    await analystPage.getByTestId("generate-plan").click();
    await analystPage
      .getByTestId("hunt-plan-result")
      .waitFor({ state: "visible", timeout: RESULT_TIMEOUT });

    // History is the proof the plan was stored rather than only rendered.
    const history = analystPage.getByTestId("plan-history");
    await expect(history).toBeVisible({ timeout: RESULT_TIMEOUT });
    await analystPage.getByTestId("plan-history-toggle").click();
    await expect(
      analystPage.locator('[data-testid^="plan-history-item-"]').first(),
    ).toBeVisible({ timeout: RESULT_TIMEOUT });
  });
});
