/**
 * Auth-redirect behaviour for the SPA.
 *
 * Every protected route must redirect anonymous users to /login.
 * After a successful login, the SPA should land back on the page
 * the user originally tried to reach (deep-link redirect).
 */
import { test, expect } from "../../fixtures/auth";
import { LoginPage } from "../../pages/login-page";

const ANON_PROTECTED_ROUTES = [
  "/",
  "/iocs",
  "/investigations/inv_anything",
  "/mitre",
  "/knowledge",
  "/playbooks",
];

for (const route of ANON_PROTECTED_ROUTES) {
  test(`anonymous GET ${route} → redirected to /login`, async ({
    anonymousPage,
  }) => {
    await anonymousPage.goto(route);
    // The SPA route guard pushes /login. Wait for the URL to settle.
    await anonymousPage.waitForURL(/\/login(\?|$)/, { timeout: 10_000 });
    expect(anonymousPage.url()).toMatch(/\/login(\?|$)/);
  });
}

test("after login, deep-link redirect lands on the original target", async ({
  anonymousPage,
}) => {
  // Visit /iocs while anonymous — captured into the redirect param.
  await anonymousPage.goto("/iocs");
  await anonymousPage.waitForURL(/\/login(\?|$)/, { timeout: 10_000 });

  const login = new LoginPage(anonymousPage);
  await login.submitWaitingForRedirect("analyst1", "analyst1");

  // After auth, the SPA must land on /iocs — NOT the default ``/``.
  // Some implementations land on /iocs directly; some go via / first.
  // We poll for the final URL within a short window.
  await anonymousPage
    .waitForURL((url) => url.pathname === "/iocs", { timeout: 10_000 })
    .catch(() => {
      // Capture the actual landing for the error message.
    });
  expect(anonymousPage.url()).toMatch(/\/iocs(\?|$)/);
});
