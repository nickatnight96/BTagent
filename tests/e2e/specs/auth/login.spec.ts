/**
 * Auth E2E — login + logout + protected-route happy paths.
 *
 * Sprint C scope. Negative cases (cross-org IDOR, JWT revocation,
 * cookie-vs-header, oversized WS) live in sibling files under
 * ``specs/auth/`` and ``specs/security/``.
 */
import { test, expect } from "@playwright/test";
import { LoginPage } from "../../pages/login-page";
import { Header } from "../../pages/header";
import { TEST_CREDENTIALS } from "../../fixtures/api-client";

test.describe("Login", () => {
  test("login page renders all required controls", async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await expect(login.form).toBeVisible();
    await expect(login.usernameInput).toBeVisible();
    await expect(login.passwordInput).toBeVisible();
    await expect(login.submitButton).toBeVisible();
  });

  test("submit is disabled until both fields are filled", async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await expect(login.submitButton).toBeDisabled();
    await login.usernameInput.fill("admin");
    // Username only — still disabled.
    await expect(login.submitButton).toBeDisabled();
    await login.passwordInput.fill("admin");
    await expect(login.submitButton).toBeEnabled();
  });

  test("password toggle flips input type", async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.passwordInput.fill("hunter2");
    await expect(login.passwordInput).toHaveAttribute("type", "password");
    await login.passwordToggle.click();
    await expect(login.passwordInput).toHaveAttribute("type", "text");
    await login.passwordToggle.click();
    await expect(login.passwordInput).toHaveAttribute("type", "password");
  });

  test("valid credentials redirect to dashboard and set the cookie", async ({
    page,
  }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.submitWaitingForRedirect(
      TEST_CREDENTIALS.admin.username,
      TEST_CREDENTIALS.admin.password,
    );
    expect(page.url()).toContain("/");
    expect(page.url()).not.toContain("/login");

    // Cookie path: backend sets ``btagent_access`` on the document
    // origin. ``page.context().cookies()`` returns the merged jar.
    const cookies = await page.context().cookies();
    const access = cookies.find((c) => c.name === "btagent_access");
    expect(access, "btagent_access cookie should be set").toBeDefined();
    expect(access?.httpOnly, "access cookie must be HttpOnly").toBe(true);

    // localStorage path: post-Phase C1 the SPA must NOT write the
    // access token to localStorage. Verify zero trace.
    const ls = await page.evaluate(() => Object.keys(window.localStorage));
    const leakedTokens = ls.filter(
      (k) => /token|access|refresh/i.test(k),
    );
    expect(leakedTokens, "no auth tokens in localStorage").toEqual([]);
  });

  test("invalid credentials show inline error and stay on /login", async ({
    page,
  }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.login("admin", "wrong-password");
    await login.expectError();
    expect(page.url()).toContain("/login");
  });

  test("nonexistent user shows error", async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.login("does-not-exist-e2e", "irrelevant");
    await login.expectError();
    expect(page.url()).toContain("/login");
  });
});

test.describe("Logout", () => {
  // The logout flow needs an authenticated session — use the persona
  // fixture rather than a fresh login per test.
  test("clicking logout clears cookies and redirects to /login", async ({
    page,
  }) => {
    // Manual login (don't use the storageState fixture — we need a
    // fresh context to assert cookies-removed cleanly).
    const login = new LoginPage(page);
    await login.goto();
    await login.submitWaitingForRedirect(
      TEST_CREDENTIALS.analyst.username,
      TEST_CREDENTIALS.analyst.password,
    );

    const header = new Header(page);
    await expect(header.logoutButton).toBeVisible();
    await header.logout();

    expect(page.url()).toContain("/login");

    // Both auth cookies must be cleared (Set-Cookie max-age=0 on the
    // logout response).
    const cookies = await page.context().cookies();
    expect(cookies.find((c) => c.name === "btagent_access")).toBeUndefined();
    expect(cookies.find((c) => c.name === "btagent_refresh")).toBeUndefined();
  });
});

test.describe("Protected route guard", () => {
  test("anonymous user is redirected to /login when hitting a protected route", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForURL("**/login", { timeout: 5_000 });
    expect(page.url()).toContain("/login");
  });

  test("anonymous user is redirected from /iocs", async ({ page }) => {
    await page.goto("/iocs");
    await page.waitForURL("**/login", { timeout: 5_000 });
  });

  test("anonymous user is redirected from /investigations/:id", async ({
    page,
  }) => {
    await page.goto("/investigations/inv_does_not_matter");
    await page.waitForURL("**/login", { timeout: 5_000 });
  });
});
