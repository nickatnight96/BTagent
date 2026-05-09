/**
 * Auth E2E — cookie + header dual-transport.
 *
 * Phase C1 made the SPA exclusively cookie-based but the backend still
 * accepts ``Authorization: Bearer …`` for CLI / mobile / unit tests.
 * These tests pin both transports against the live API surface so a
 * future "remove the header path" change won't accidentally break the
 * CLI flow.
 */
import { test, expect } from "@playwright/test";
import { BTAgentApiClient, TEST_CREDENTIALS } from "../../fixtures/api-client";

test("cookie-auth client can read /auth/me", async () => {
  const api = await BTAgentApiClient.loginWithCookie(TEST_CREDENTIALS.analyst);
  const res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.username).toBe("analyst1");
  await api.dispose();
});

test("header-auth client can read /auth/me without a cookie", async () => {
  const api = await BTAgentApiClient.loginWithHeaderToken(
    TEST_CREDENTIALS.analyst,
  );
  expect(api.accessToken).toBeTruthy();
  const res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(200);
  const body = await res.json();
  expect(body.username).toBe("analyst1");
  await api.dispose();
});

test("logout revokes the access token's jti — subsequent calls 401", async () => {
  const api = await BTAgentApiClient.loginWithHeaderToken(
    TEST_CREDENTIALS.analyst,
  );
  // First call: works.
  let res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(200);

  await api.logout();

  // The token is in the revocation list — the same token can no
  // longer authenticate even though its TTL has not expired.
  res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(401);
  const wwwAuth = res.headers()["www-authenticate"] ?? "";
  expect(wwwAuth).toContain("invalid_token");
  await api.dispose();
});

test("after refresh, the old refresh token is revoked", async () => {
  // Login via cookie path; the refresh cookie is in the jar.
  const api = await BTAgentApiClient.loginWithCookie(TEST_CREDENTIALS.analyst);
  // Read both cookies.
  const cookiesBefore = await api.ctx.storageState();
  const refreshBefore = cookiesBefore.cookies.find(
    (c) => c.name === "btagent_refresh",
  );
  expect(refreshBefore).toBeDefined();

  // Rotate.
  const refresh = await api.ctx.post("/api/v1/auth/refresh", { data: {} });
  expect(refresh.status()).toBe(200);

  const cookiesAfter = await api.ctx.storageState();
  const refreshAfter = cookiesAfter.cookies.find(
    (c) => c.name === "btagent_refresh",
  );
  expect(refreshAfter).toBeDefined();
  expect(refreshAfter?.value).not.toBe(refreshBefore?.value);

  await api.dispose();
});
