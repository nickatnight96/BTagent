/**
 * Accessibility coverage — login surface.
 *
 * The login page is unauthenticated and a small DOM, so it's the
 * cheapest place to start enforcing zero serious/critical a11y
 * violations. Successful here, the same pattern extends to every
 * post-auth surface in the matching ``a11y/*.spec.ts`` files.
 */
import { test } from "@playwright/test";
import { expectNoA11yViolations } from "../../fixtures/a11y";
import { LoginPage } from "../../pages/login-page";

test("login surface is free of critical/serious a11y violations", async ({
  page,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await expectNoA11yViolations(page);
});

test("login form interactions don't introduce a11y violations", async ({
  page,
}) => {
  const login = new LoginPage(page);
  await login.goto();
  await login.usernameInput.fill("admin");
  await login.passwordInput.fill("admin");
  // Toggle the password visibility — exercises the icon-only button
  // that gained an aria-label in Sprint A.
  await login.passwordToggle.click();
  await expectNoA11yViolations(page);
});
