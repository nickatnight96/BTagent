/**
 * Setup project — runs once before any test. Logs each persona in via
 * the UI and dumps ``storageState`` to ``.auth/{persona}.json`` so the
 * persona fixtures can hydrate a context without re-doing the login
 * round-trip per test.
 *
 * Going through the UI on purpose (rather than calling /auth/login
 * directly) so that a regression in the login form itself fails the
 * setup loudly instead of letting tests pass against a broken UI.
 */
import { test as setup, expect } from "@playwright/test";
import { TEST_CREDENTIALS, type AuthCredentials } from "../fixtures/api-client";

const PERSONA_FILES: Record<keyof typeof TEST_CREDENTIALS, string> = {
  admin: ".auth/admin.json",
  analyst: ".auth/analyst.json",
  senior: ".auth/senior.json",
};

async function loginAndPersist(
  page: import("@playwright/test").Page,
  creds: AuthCredentials,
  storageStatePath: string,
): Promise<void> {
  await page.goto("/login");
  await page.getByTestId("login-username-input").fill(creds.username);
  await page.getByTestId("login-password-input").fill(creds.password);
  await page.getByTestId("login-submit-button").click();
  // Server sets the cookie on success; the SPA navigates to ``/`` on
  // login. Wait for the navigation rather than for any specific
  // dashboard text — the dashboard tests own the rendering checks.
  await page.waitForURL((url) => !url.pathname.endsWith("/login"), {
    timeout: 15_000,
  });
  // Sanity assertion before persisting state — if the cookie didn't
  // land or the redirect bounced back to /login, we'd write a
  // half-broken storage state and every persona test would fail.
  await expect(page.getByTestId("header")).toBeVisible({ timeout: 10_000 });
  await page.context().storageState({ path: storageStatePath });
}

setup("authenticate as admin", async ({ page }) => {
  await loginAndPersist(page, TEST_CREDENTIALS.admin, PERSONA_FILES.admin);
});

setup("authenticate as analyst", async ({ page }) => {
  await loginAndPersist(page, TEST_CREDENTIALS.analyst, PERSONA_FILES.analyst);
});

setup("authenticate as senior", async ({ page }) => {
  await loginAndPersist(page, TEST_CREDENTIALS.senior, PERSONA_FILES.senior);
});
