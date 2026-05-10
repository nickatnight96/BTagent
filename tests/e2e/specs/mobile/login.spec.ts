/**
 * @mobile — login + dashboard on a Pixel-7-sized viewport.
 *
 * These tests are tagged ``@mobile`` so the ``mobile-chrome``
 * project (``make e2e-mobile``) picks them up. The default
 * ``chromium`` project does NOT filter by tag, so it would also
 * pick these specs up at the desktop 1280×720 viewport — the
 * ``header-menu-toggle`` is ``md:hidden`` and the test would fail
 * because the toggle is intentionally not rendered above 768 px.
 *
 * Fix: ``test.use({ viewport })`` forces a 412×915 viewport
 * regardless of which project runs the spec, so the
 * ``md:hidden`` boundary is reliably crossed.
 */
import { test, expect, devices } from "@playwright/test";
import { LoginPage } from "../../pages/login-page";
import { TEST_CREDENTIALS } from "../../fixtures/api-client";

test.use({ viewport: devices["Pixel 7"]?.viewport ?? { width: 412, height: 915 } });

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
  // sub-768 px viewports. The ``test.use`` above forces a 412 px
  // viewport so this assertion is reliable in every project.
  await expect(page.getByTestId("header-menu-toggle")).toBeVisible();
});
