/**
 * @cross-browser — auth flow on Firefox + WebKit.
 *
 * Tagged with ``@cross-browser`` so the firefox / webkit projects pick
 * it up (default ``make e2e`` only runs Chromium-desktop). Use to
 * pin browser-specific behaviours of the new cookie-auth / WS-via-
 * cookie surfaces — Safari's ``SameSite`` interpretation has bitten
 * us before and should bite a test, not a customer.
 */
import { test, expect } from "@playwright/test";
import { LoginPage } from "../../pages/login-page";
import { TEST_CREDENTIALS } from "../../fixtures/api-client";

test("login + cookie set works on this browser @cross-browser", async ({
  page,
  browserName,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await login.submitWaitingForRedirect(
    TEST_CREDENTIALS.analyst.username,
    TEST_CREDENTIALS.analyst.password,
  );
  const cookies = await page.context().cookies();
  const access = cookies.find((c) => c.name === "btagent_access");
  expect(
    access,
    `btagent_access cookie should be set on ${browserName}`,
  ).toBeDefined();
  expect(access?.httpOnly).toBe(true);
});

test("logout clears cookies on this browser @cross-browser", async ({
  page,
  browserName,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await login.submitWaitingForRedirect(
    TEST_CREDENTIALS.analyst.username,
    TEST_CREDENTIALS.analyst.password,
  );
  await page.getByTestId("header-logout-button").click();
  await page.waitForURL("**/login");
  const cookies = await page.context().cookies();
  expect(
    cookies.find((c) => c.name === "btagent_access"),
    `${browserName} should clear access cookie on logout`,
  ).toBeUndefined();
});
