/**
 * CORS allow-list enforcement.
 *
 * Backend ``allow_origins`` is configured per-env. The test
 * environment includes ``http://localhost:5173`` (Vite dev) and
 * ``http://localhost:3001`` (fallback port). Any other origin must
 * be denied — both for the OPTIONS preflight and for actual requests.
 */
import { request, type APIRequestContext } from "@playwright/test";
import { test, expect } from "../../fixtures/auth";

const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";

async function preflight(
  origin: string,
): Promise<{ status: number; headers: Record<string, string> }> {
  const ctx: APIRequestContext = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
  const res = await ctx.fetch("/api/v1/investigations", {
    method: "OPTIONS",
    headers: {
      Origin: origin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type,authorization",
    },
  });
  const headers = res.headers();
  await ctx.dispose();
  return { status: res.status(), headers };
}

test("preflight from a disallowed origin → no allow-origin echo", async () => {
  const { status, headers } = await preflight("https://evil.example");
  // The server may either refuse outright (4xx) or return 200/204 with
  // CORS headers MISSING — either way, the browser would block. We
  // assert the allow-origin header does NOT echo evil.example.
  void status;
  const allowOrigin = headers["access-control-allow-origin"] ?? "";
  expect(allowOrigin).not.toBe("https://evil.example");
  expect(allowOrigin).not.toBe("*");
});

test("preflight from the configured Vite origin → allowed", async () => {
  // The test env should include localhost:5173 OR localhost:3001.
  // Try both — at least one must be allowed.
  const candidates = ["http://localhost:5173", "http://localhost:3001"];
  let anyAllowed = false;
  for (const origin of candidates) {
    const { headers } = await preflight(origin);
    const allow = headers["access-control-allow-origin"] ?? "";
    if (allow === origin) {
      anyAllowed = true;
      break;
    }
  }
  expect(anyAllowed).toBe(true);
});

test("POST from a disallowed origin → no allow-origin echo on response", async () => {
  // Simulate the CORS-disallowed POST. We can't make the browser
  // actually drop the response (Playwright forces fetch through
  // anyway), but we CAN assert the response lacks the allow-origin
  // header — which is what the browser checks.
  const ctx = await request.newContext({
    baseURL: API_URL,
    extraHTTPHeaders: {
      "x-e2e-test": "1",
      Origin: "https://evil.example",
    },
  });
  const res = await ctx.post("/api/v1/auth/login", {
    data: { username: "no-such-user", password: "wrong" },
  });
  const headers = res.headers();
  const allow = headers["access-control-allow-origin"] ?? "";
  expect(allow).not.toBe("https://evil.example");
  expect(allow).not.toBe("*");
  await ctx.dispose();
});
