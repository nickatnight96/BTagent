/**
 * Detection Validation page E2E (#118).
 *
 * The last routed page with no browser coverage. It is also the page with the
 * most safety-relevant control in the product: `POST /validation/emulate`
 * fires an ATT&CK technique, and the only thing standing between an operator
 * and a non-sandbox target is a fail-closed server allowlist.
 *
 * The two tests that carry their weight here are about *refusals*:
 *
 *  - A non-sandbox target must come back as an audited **outcome**, not an
 *    error: the denial panel with its ledger `audit_id`, no verdicts, and no
 *    validation run persisted. The audit id is the operator's only pointer
 *    into the trail; rendering "request failed" would throw it away.
 *  - A plain RBAC 403 and a sandbox denial are *different 403s*, and
 *    `emulationDenial()` distinguishes them purely by the presence of
 *    `audit_id`. This spec pins both shapes, because normalising error bodies
 *    would either make the denial panel render for ordinary permission
 *    failures or stop it rendering for real refusals — and both regressions
 *    are silent.
 *
 * Mock-first throughout: the emulator is pinned to mock mode, so nothing here
 * executes a real technique. Live ART remains gated on the #118 sign-off.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

const PAGE_TIMEOUT = 10_000;
const RUN_TIMEOUT = 30_000;

async function openPage(page: Page): Promise<void> {
  await page.goto("/detection-validation");
  await page
    .getByTestId("detection-validation")
    .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
}

/** Rows currently in the run-history table (0 when the empty state shows). */
async function runRowCount(page: Page): Promise<number> {
  return page.locator('[data-testid^="validation-run-"]').count();
}

/** Wait for the initial run-history fetch to settle before reading a count. */
async function historyLoaded(page: Page): Promise<void> {
  await expect(
    page.getByTestId("validation-runs-table").or(page.getByText("No validation runs yet")),
  ).toBeVisible({ timeout: PAGE_TIMEOUT });
}

test.describe("Detection Validation page", () => {
  test("page structure renders — history controls and the coverage map", async ({
    analystPage,
  }) => {
    await openPage(analystPage);

    await expect(
      analystPage.getByRole("heading", { name: "Detection Validation" }),
    ).toBeVisible();
    await expect(analystPage.getByTestId("validation-refresh")).toBeVisible();
    await expect(analystPage.getByTestId("validation-run")).toBeVisible();
    await expect(analystPage.getByTestId("coverage-map-panel")).toBeVisible();
  });

  test("sidebar nav link reaches the page", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("nav-detection-validation-link").click();
    await analystPage
      .getByTestId("detection-validation")
      .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
    expect(analystPage.url()).toContain("/detection-validation");
  });

  test("running a validation lands a row in the run history", async ({ adminPage }) => {
    await openPage(adminPage);
    // Count only after the initial fetch resolves — reading straight after
    // navigation gets 0 rows and turns any later row into a false pass.
    await historyLoaded(adminPage);
    const before = await runRowCount(adminPage);

    await adminPage.getByTestId("validation-run").click();

    // The history is the persistence proof — a run that renders but is not
    // stored tells the analyst nothing about coverage over time.
    await expect
      .poll(() => runRowCount(adminPage), {
        timeout: RUN_TIMEOUT,
        message: "no new run row appeared after triggering a validation",
      })
      .toBeGreaterThan(before);
    await expect(adminPage.getByTestId("validation-runs-table")).toBeVisible();
  });

  test("a non-sandbox target is refused as an audited outcome, and nothing ran", async ({
    adminPage,
  }) => {
    await openPage(adminPage);
    await expect(adminPage.getByTestId("emulation-panel")).toBeVisible();

    await adminPage.getByTestId("emulation-technique").fill("T1059");
    await adminPage.getByTestId("emulation-target-env").selectOption("production");
    await adminPage.getByTestId("emulation-run").click();

    // Rendered as a refusal with a ledger pointer, not as a failed request.
    const denial = adminPage.getByTestId("emulation-denied");
    await expect(denial).toBeVisible({ timeout: RUN_TIMEOUT });
    await expect(denial).toContainText("Refused");
    await expect(denial).toContainText("production");
    await expect(adminPage.getByTestId("emulation-denied-audit")).not.toBeEmpty();

    // No emulator was reached: nothing was scored...
    await expect(adminPage.getByTestId("emulation-verdicts")).toHaveCount(0);

    // ...and no run was persisted for a non-sandbox target. Asserted as an
    // invariant over the whole history rather than a before/after row count:
    // the org's run list is shared, so parallel shards move the count, but
    // "no run exists whose target_env is outside the sandbox allowlist" holds
    // no matter who else is writing.
    const resp = await adminPage.request.get("/api/v1/validation/runs?limit=200");
    expect(resp.ok()).toBeTruthy();
    const { items } = (await resp.json()) as {
      items: Array<{ target_env: string | null }>;
    };
    expect(
      items.filter((r) => r.target_env != null && r.target_env !== "sandbox"),
    ).toEqual([]);
  });

  test("a sandbox emulation scores the technique and is flagged in history", async ({
    adminPage,
  }) => {
    await openPage(adminPage);

    await adminPage.getByTestId("emulation-technique").fill("T1059");
    await adminPage.getByTestId("emulation-target-env").selectOption("sandbox");
    await adminPage.getByTestId("emulation-run").click();

    await expect(adminPage.getByTestId("emulation-verdict-T1059")).toBeVisible({
      timeout: RUN_TIMEOUT,
    });
    await expect(adminPage.getByTestId("emulation-denied")).toHaveCount(0);

    // Emulation and synthetic replay land in the same table; a run that
    // actually fired a technique must not be indistinguishable from a replay.
    await expect(
      adminPage.locator('[data-testid^="validation-run-emulated-"]').first(),
    ).toBeVisible({ timeout: RUN_TIMEOUT });
  });

  test("an analyst gets no emulation control, and the RBAC 403 is not a denial", async ({
    analystPage,
  }) => {
    await openPage(analystPage);

    // validation:emulate is gated at incident_commander, like containment.
    await expect(analystPage.getByTestId("emulation-panel")).toHaveCount(0);
    // The read-only half of the page still works for them.
    await expect(analystPage.getByTestId("coverage-map-panel")).toBeVisible();

    const resp = await analystPage.request.post("/api/v1/validation/emulate", {
      data: { technique_id: "T1059", target_env: "sandbox", emulator: "atomic_red_team" },
    });
    expect(resp.status()).toBe(403);

    // Shape matters, not just the status: `emulationDenial()` treats a 403 as a
    // sandbox refusal only when the body carries `audit_id`. An RBAC refusal
    // has a plain string detail and no ledger row, so it must NOT be dressed up
    // as an audited denial.
    const body = (await resp.json()) as { detail?: unknown };
    expect(typeof body.detail).toBe("string");
  });

  test("coverage map 'Validate' loads the technique without firing it", async ({
    adminPage,
  }) => {
    // Emulating first guarantees at least one technique carries coverage data,
    // whatever detections the environment happens to be seeded with.
    await openPage(adminPage);
    await adminPage.getByTestId("emulation-technique").fill("T1059");
    await adminPage.getByTestId("emulation-target-env").selectOption("sandbox");
    await adminPage.getByTestId("emulation-run").click();
    await expect(adminPage.getByTestId("emulation-verdict-T1059")).toBeVisible({
      timeout: RUN_TIMEOUT,
    });

    // The coverage map loads on mount, so reload to pick up that run. T1059 is
    // now validated *today*, i.e. deliberately not stale — clearing the
    // stale-only default is what brings it into view.
    await openPage(adminPage);
    await adminPage.getByTestId("coverage-map-stale-only").uncheck();
    const row = adminPage.getByTestId("coverage-map-row-T1059");
    await expect(row).toBeVisible({ timeout: PAGE_TIMEOUT });
    await expect(adminPage.getByTestId("coverage-map-age-T1059")).toContainText("today");

    // Watch for the fire-a-technique call itself rather than counting rows in
    // the org-shared history: this is the precise claim, and it cannot be
    // perturbed by another shard writing runs concurrently.
    let emulateCalls = 0;
    adminPage.on("request", (req) => {
      if (req.method() === "POST" && req.url().includes("/validation/emulate")) {
        emulateCalls += 1;
      }
    });

    await adminPage.getByTestId("coverage-map-validate-T1059").click();

    // Hand-off fills the field and stops. This control fires a technique, so
    // the operator still has to press the button — a "Validate" that quietly
    // emulated would be a one-click execution path.
    await expect(adminPage.getByTestId("emulation-technique")).toHaveValue("T1059");
    await adminPage.waitForTimeout(1500);
    await expect(adminPage.getByTestId("emulation-verdicts")).toHaveCount(0);
    expect(emulateCalls).toBe(0);
  });
});
