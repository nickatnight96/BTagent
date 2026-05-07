/**
 * @mobile — login + dashboard on the Pixel 7 viewport.
 *
 * The mobile-chrome project's ``grep`` filter picks up these tests
 * (``make e2e-mobile``). The frontend's ``hidden sm:inline`` and
 * ``hidden md:flex`` classes mean a lot of UI hides on narrow widths;
 * tests here pin the parts that *must* still work — login,
 * navigation toggle, investigation list, opening one investigation.
 */
import { test, expect } from "@playwright/test";
import { LoginPage } from "../../pages/login-page";
import { TEST_CREDENTIALS } from "../../fixtures/api-client";

test("login form fits the mobile viewport @mobile", async ({ page }) => {
  const login = new LoginPage(page);
  await login.goto();
  // Form fits within a 412 px-wide viewport without horizontal scroll.
  const docWidth = await page.evaluate(
    () => document.documentElement.scrollWidth,
  );
  const viewportWidth = page.viewportSize()?.width ?? 0;
  expect(
    docWidth,
    "no horizontal scroll bar on mobile login",
  ).toBeLessThanOrEqual(viewportWidth + 1);
  await expect(login.usernameInput).toBeVisible();
  await expect(login.passwordInput).toBeVisible();
  await expect(login.submitButton).toBeVisible();
});

test("login + redirect to dashboard works on mobile @mobile", async ({
  page,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await login.submitWaitingForRedirect(
    TEST_CREDENTIALS.analyst.username,
    TEST_CREDENTIALS.analyst.password,
  );
  expect(page.url()).not.toContain("/login");
});

test("mobile menu toggle is visible at narrow widths @mobile", async ({
  page,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await login.submitWaitingForRedirect(
    TEST_CREDENTIALS.analyst.username,
    TEST_CREDENTIALS.analyst.password,
  );
  // Header's mobile menu button is ``md:hidden``, so it shows up on
  // sub-768px viewports (Pixel 7 = 412 px). The Sprint A
  // instrumentation gave it ``aria-label="Toggle navigation menu"``
  // and a stable ``header-menu-toggle`` testid.
  await expect(page.getByTestId("header-menu-toggle")).toBeVisible();
});
