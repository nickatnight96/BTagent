/**
 * Rate-limit / brute-force protection.
 *
 * The login endpoint must throttle once a fixed number of failed
 * attempts come from the same client. The middleware response should
 * include a ``Retry-After`` header so well-behaved clients back off.
 *
 * We use a dedicated APIRequestContext so the backend's per-client
 * limiter sees one consistent caller throughout the test.
 */
import {
  request,
  type APIRequestContext,
  type APIResponse,
} from "@playwright/test";
import { test, expect } from "../../fixtures/auth";

const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";

async function freshClient(): Promise<APIRequestContext> {
  return request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
}

test("repeated bad logins → 429 after the threshold @nginx", async () => {
  const ctx = await freshClient();
  let saw429 = false;
  let saw401AtLeastOnce = false;

  // Cap the loop. 20 is comfortably above any reasonable threshold
  // (per the FastAPI rate-limit middleware default of 5/min) without
  // running so long that a flake takes minutes.
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await ctx.post("/api/v1/auth/login", {
      data: { username: "no-such-user", password: "wrong-secret-XYZ" },
    });
    if (res.status() === 401) saw401AtLeastOnce = true;
    if (res.status() === 429) {
      saw429 = true;
      break;
    }
  }
  expect(saw401AtLeastOnce).toBe(true);
  expect(saw429).toBe(true);
  await ctx.dispose();
});

test("the throttled response includes a Retry-After header @nginx", async () => {
  const ctx = await freshClient();
  let throttled: APIResponse | null = null;
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await ctx.post("/api/v1/auth/login", {
      data: { username: "no-such-user-2", password: "still-wrong" },
    });
    if (res.status() === 429) {
      throttled = res;
      break;
    }
  }
  expect(throttled).not.toBeNull();
  if (throttled) {
    const headers = throttled.headers();
    // Some implementations name it ``retry-after`` (lower) per RFC.
    const retryAfter =
      headers["retry-after"] ?? headers["Retry-After".toLowerCase()];
    expect(retryAfter).toBeTruthy();
  }
  await ctx.dispose();
});

test.skip(
  "non-login endpoints currently inherit only the global limit",
  async () => {
    // TODO: BTagent's middleware applies a stricter cap on
    // /api/v1/auth/login than on the other endpoints. When per-route
    // limits are added (e.g. /knowledge/ingest, /iocs bulk), expand
    // this case to exercise them. Skipped intentionally so future
    // engineers see the gap.
  },
);
