/**
 * JWT revocation — both transports.
 *
 * The backend keeps a per-jti revocation list (Redis-backed). On
 * logout, the access-token jti is added to it. On refresh, BOTH the
 * old refresh-token jti and the old access-token jti are revoked,
 * forcing the rotation contract.
 *
 * Reproduces the patterns from the cookie-vs-header.spec.ts reference
 * but extends them across the additional revocation paths.
 */
import { request } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";
import {
  BTAgentApiClient,
  TEST_CREDENTIALS,
} from "../../fixtures/api-client";

const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";

test("cookie path: logout revokes the access token's jti", async () => {
  const api = await BTAgentApiClient.loginWithCookie(TEST_CREDENTIALS.analyst);

  let res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(200);

  await api.logout();

  res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(401);

  await api.dispose();
});

test("header path: logout revokes the access token's jti", async () => {
  const api = await BTAgentApiClient.loginWithHeaderToken(
    TEST_CREDENTIALS.analyst,
  );

  let res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(200);

  await api.logout();

  res = await api.ctx.get("/api/v1/auth/me");
  expect(res.status()).toBe(401);
  const wwwAuth = res.headers()["www-authenticate"] ?? "";
  expect(wwwAuth).toContain("invalid_token");

  await api.dispose();
});

test("after refresh, the OLD refresh token is revoked", async () => {
  const api = await BTAgentApiClient.loginWithCookie(TEST_CREDENTIALS.analyst);

  // Snapshot the original refresh cookie value.
  const before = await api.ctx.storageState();
  const refreshBefore = before.cookies.find(
    (c) => c.name === "btagent_refresh",
  );
  expect(refreshBefore).toBeDefined();

  // Rotate.
  const refresh = await api.ctx.post("/api/v1/auth/refresh", { data: {} });
  expect(refresh.status()).toBe(200);

  // Replay: build a fresh APIRequestContext that holds ONLY the
  // original refresh cookie. The server should reject the rotation
  // attempt because that jti is now in the revocation list.
  const replayCtx = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: { "x-e2e-test": "1" },
    storageState: {
      cookies: refreshBefore ? [refreshBefore] : [],
      origins: [],
    },
  });
  const replayRes = await replayCtx.post("/api/v1/auth/refresh", { data: {} });
  expect([401, 403]).toContain(replayRes.status());

  await replayCtx.dispose();
  await api.dispose();
});

test("after refresh, the OLD access token's jti is revoked", async () => {
  // Use header transport so we can hold the literal old token in
  // memory and replay it.
  const api = await BTAgentApiClient.loginWithHeaderToken(
    TEST_CREDENTIALS.analyst,
  );
  const oldToken = api.accessToken;
  expect(oldToken).toBeTruthy();

  // Rotate.
  const refresh = await api.ctx.post("/api/v1/auth/refresh", { data: {} });
  expect(refresh.status()).toBe(200);

  // Replay the OLD access token via a fresh context bound only to it.
  const replay = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: {
      "x-e2e-test": "1",
      Authorization: `Bearer ${oldToken}`,
    },
  });
  const res = await replay.get("/api/v1/auth/me");
  expect(res.status()).toBe(401);
  const wwwAuth = res.headers()["www-authenticate"] ?? "";
  expect(wwwAuth).toContain("invalid_token");

  await replay.dispose();
  await api.dispose();
});
