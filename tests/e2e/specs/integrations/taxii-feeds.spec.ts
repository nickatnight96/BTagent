/**
 * TAXII feed subscriptions panel E2E (#105 / #516).
 *
 * Browser-level coverage of the admin screen on Settings → Integrations:
 *  - admin CRUD round-trip (add → disable → two-step delete), leaving the DB
 *    clean and using a timestamped feed name so re-runs against a dirty
 *    database never collide;
 *  - the reference-only credential contract: raw material in
 *    ``auth_secret_ref`` is refused with the server's 422 shown verbatim, and
 *    no feed row is created;
 *  - RBAC self-effacement: senior_analyst gets the read-only panel (no form,
 *    no manage buttons), a plain analyst gets no panel at all — the UI half
 *    of the taxii:view / taxii:manage server gates.
 *
 * The unit suite covers the panel against a mocked API; this spec is the one
 * place the real ``/taxii/feeds`` routes, their validation wording, and the
 * role-scoped storageStates meet.
 */

import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

async function gotoIntegrations(page: Page) {
  await page.goto("/integrations");
  // The connector-count line renders once GET /connectors resolves; the TAXII
  // panel does its own fetch and mounts below the catalog.
  await page.getByTestId("connector-count").waitFor({ state: "visible", timeout: 15_000 });
}

test.describe("TAXII feeds panel", () => {
  test("admin can add, disable and two-step-delete a feed", async ({ adminPage }) => {
    const name = `E2E TAXII ${Date.now()}`;

    await gotoIntegrations(adminPage);
    await adminPage.getByTestId("taxii-feeds-panel").waitFor({ state: "visible", timeout: 15_000 });

    // Add — auth_style stays "none", so the secret-ref field must stay empty
    // (the server 422s a ref that nothing would use).
    await adminPage.getByTestId("taxii-feed-name").fill(name);
    await adminPage.getByTestId("taxii-feed-url").fill("https://taxii.e2e.example/api1");
    await adminPage.getByTestId("taxii-feed-collection").fill(`col-${Date.now()}`);
    await adminPage.getByTestId("taxii-feed-create").click();

    const row = adminPage.locator('[data-testid="taxii-feeds-list"] li', { hasText: name });
    await expect(row).toBeVisible({ timeout: 10_000 });
    // Fresh feeds are enabled with empty sweep telemetry.
    await expect(row.getByTestId("taxii-feed-status")).toHaveText("pending first poll");

    // Disable — the status chip flips rather than the row disappearing, so a
    // paused feed stays visible instead of silently vanishing from the org.
    await row.locator('[data-testid^="taxii-feed-toggle-"]').click();
    await expect(row.getByTestId("taxii-feed-status")).toHaveText("disabled", {
      timeout: 10_000,
    });

    // Delete is two-step: the first click only arms the confirmation.
    const deleteBtn = row.locator('[data-testid^="taxii-feed-delete-"]');
    await deleteBtn.click();
    await expect(deleteBtn).toHaveText(/Confirm delete/);
    await expect(row).toBeVisible();
    await deleteBtn.click();
    await expect(row).toBeHidden({ timeout: 10_000 });
  });

  test("raw credential material is refused with the server's 422 and nothing is created", async ({
    adminPage,
  }) => {
    const name = `E2E TAXII raw-cred ${Date.now()}`;

    await gotoIntegrations(adminPage);
    await adminPage.getByTestId("taxii-feeds-panel").waitFor({ state: "visible", timeout: 15_000 });

    await adminPage.getByTestId("taxii-feed-name").fill(name);
    await adminPage.getByTestId("taxii-feed-url").fill("https://taxii.e2e.example/api1");
    await adminPage.getByTestId("taxii-feed-collection").fill(`col-raw-${Date.now()}`);
    await adminPage.getByTestId("taxii-feed-auth-style").selectOption("bearer");
    // A literal token where a ${secret:...} / ${env:VAR} reference belongs.
    await adminPage.getByTestId("taxii-feed-secret-ref").fill("hunter2-raw-bearer-token");
    await adminPage.getByTestId("taxii-feed-create").click();

    // The panel surfaces the server's wording verbatim, not a flattened
    // "failed" — the message is the operator's fix instruction.
    const error = adminPage.getByTestId("taxii-feeds-error");
    await expect(error).toBeVisible({ timeout: 10_000 });
    await expect(error).toContainText("raw credential material is never stored");

    // Nothing was persisted.
    await expect(
      adminPage.locator('[data-testid="taxii-feeds-list"] li', { hasText: name }),
    ).toHaveCount(0);
  });

  test("senior analyst sees the panel read-only — no form, no manage buttons", async ({
    seniorPage,
  }) => {
    await gotoIntegrations(seniorPage);
    // taxii:view is senior_analyst+, so the panel itself renders...
    await seniorPage
      .getByTestId("taxii-feeds-panel")
      .waitFor({ state: "visible", timeout: 15_000 });

    // ...but every taxii:manage affordance is absent: no add form, no
    // enable/disable, no delete.
    await expect(seniorPage.getByTestId("taxii-feed-form")).toHaveCount(0);
    await expect(seniorPage.locator('[data-testid^="taxii-feed-toggle-"]')).toHaveCount(0);
    await expect(seniorPage.locator('[data-testid^="taxii-feed-delete-"]')).toHaveCount(0);
  });

  test("plain analyst gets no TAXII panel at all", async ({ analystPage }) => {
    // Below taxii:view the panel self-effaces entirely — feed server URLs and
    // collection ids are org CTI-sourcing configuration, not analyst material.
    await gotoIntegrations(analystPage);
    await expect(analystPage.getByTestId("taxii-feeds-panel")).toHaveCount(0);
  });
});
