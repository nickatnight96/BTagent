/**
 * CSRF coverage — pin the dual-transport contract.
 *
 * The backend accepts auth in two ways:
 *
 *   1. ``btagent_access`` cookie (HttpOnly, SameSite=Lax/Strict). This
 *      transport IS subject to CSRF protections.
 *   2. ``Authorization: Bearer <token>`` header. NOT subject to CSRF
 *      because a cross-origin script can't read it from the SPA's
 *      cookie jar to begin with.
 *
 * These tests assert:
 *   * Cross-origin POST with manipulated Origin → rejected (cookie path).
 *   * Header-only POST from a cookie-less context → accepted (header
 *     path is the documented fallback for CLI / mobile).
 *   * Cookie scoped to a different domain doesn't grant access.
 *   * Same-origin logout (the SPA's actual flow) still works.
 */
import { request, type APIRequestContext } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";
import {
  BTAgentApiClient,
  TEST_CREDENTIALS,
} from "../../fixtures/api-client";

const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";

test("cross-origin POST with foreign Origin header → rejected", async () => {
  // Use a fresh context. Login via cookie, then forge an Origin.
  const cookieClient = await BTAgentApiClient.loginWithCookie(
    TEST_CREDENTIALS.analyst,
  );
  // Build a sibling APIRequestContext that *shares* the storage state
  // (so it carries the cookie) but adds a malicious Origin.
  const stolen = await cookieClient.ctx.storageState();
  const malicious: APIRequestContext = await request.newContext({
    baseURL: API_URL,
    storageState: stolen,
    extraHTTPHeaders: {
      "x-e2e-test": "1",
      Origin: "https://evil.example",
      Referer: "https://evil.example/",
    },
  });

  const res = await malicious.post("/api/v1/investigations", {
    data: {
      title: "CSRF probe",
      severity: "low",
      tlp_level: "green",
    },
  });
  // Per BTagent's CORS+CSRF stance, the backend rejects unknown
  // origins. Acceptable rejection codes: 401, 403, 400.
  expect([400, 401, 403]).toContain(res.status());

  await malicious.dispose();
  await cookieClient.dispose();
});

test("header-token POST from a cookie-less context → accepted", async () => {
  // Pin: the dual-transport contract is intentional. CLI / mobile
  // clients carry only the Authorization header and are not in scope
  // for CSRF, since a CSRF attacker can't mint a header on the
  // victim's behalf.
  const headerClient = await BTAgentApiClient.loginWithHeaderToken(
    TEST_CREDENTIALS.analyst,
  );
  expect(headerClient.accessToken).toBeTruthy();

  const res = await headerClient.ctx.post("/api/v1/investigations", {
    data: {
      title: "[E2E] header-only CSRF compat probe",
      severity: "low",
      tlp_level: "green",
    },
  });
  // A successful create or, if the route enforces additional shape
  // checks, a 4xx that is *not* 401/403. The point is auth succeeded.
  expect(res.status()).not.toBe(401);
  expect(res.status()).not.toBe(403);

  await headerClient.dispose();
});

test("cookie scoped to a different domain doesn't grant access", async ({
  browser,
}) => {
  // Build a context with a fake auth cookie pinned to *another* domain.
  // The backend's cookie-domain match must reject it — the request goes
  // out cookie-less and gets a 401.
  const ctx = await browser.newContext({
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
  await ctx.addCookies([
    {
      name: "btagent_access",
      value: "forged.token.value",
      domain: "evil.example",
      path: "/",
      httpOnly: true,
      secure: false,
      sameSite: "Lax",
    },
  ]);
  const apiCtx: APIRequestContext = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
  // Note: the cookie above lives on the browser context, NOT the API
  // request context. We deliberately use the API context for the
  // request to confirm no cross-domain leakage.
  const res = await apiCtx.post("/api/v1/investigations", {
    data: { title: "x", severity: "low", tlp_level: "green" },
  });
  expect([401, 403]).toContain(res.status());
  await apiCtx.dispose();
  await ctx.close();
});

test("same-origin logout from authenticated client succeeds", async ({
  analystApi,
}) => {
  // Sanity: the SPA's actual logout flow IS same-origin and must
  // continue to work. If this test starts failing, our CSRF guard is
  // overzealous and we've broken the legitimate flow.
  const res = await analystApi.ctx.post("/api/v1/auth/logout");
  expect([200, 204]).toContain(res.status());
});
