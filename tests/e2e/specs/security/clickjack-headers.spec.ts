/**
 * Clickjack / supply-chain hardening headers.
 *
 * Pin the response-header policy so a future framework upgrade or
 * proxy reconfiguration can't silently regress the supply-chain
 * hardening commit.
 *
 * Tagged ``@nginx``: these headers (X-Frame-Options, X-Content-Type-
 * Options, HSTS, CSP) are emitted by nginx in production
 * (``infra/nginx/nginx.conf``) — ``vite preview`` does not add them
 * in dev. The default chromium-desktop project's ``grepInvert``
 * filters @nginx out; run ``--project=nginx`` against the full
 * Docker stack to engage these.
 */
import { test, expect } from "../../fixtures/auth";

test("authenticated /  ships X-Frame, nosniff, HSTS, CSP @nginx", async ({
  analystApi,
}) => {
  const res = await analystApi.ctx.get("/");
  // The SPA root may serve via the frontend dev-server; we exercise
  // the API origin the SPA actually talks to. If the test env's
  // frontend serves the document, the same headers are also expected
  // via the reverse proxy.
  expect(res.status()).toBeLessThan(500);
  const h = res.headers();

  const xFrame = h["x-frame-options"] ?? "";
  expect(xFrame.toUpperCase()).toMatch(/DENY|SAMEORIGIN/);

  const xCto = h["x-content-type-options"] ?? "";
  expect(xCto.toLowerCase()).toBe("nosniff");

  const hsts = h["strict-transport-security"] ?? "";
  expect(hsts).toMatch(/max-age=\d+/);

  const csp = h["content-security-policy"] ?? "";
  expect(csp.length).toBeGreaterThan(0);
});

test("CSP does NOT permit unsafe-inline for script-src @nginx", async ({
  analystApi,
}) => {
  const res = await analystApi.ctx.get("/");
  const csp = (res.headers()["content-security-policy"] ?? "").toLowerCase();
  // Acceptable: missing script-src (falls back to default-src) OR
  // present without 'unsafe-inline'. Forbidden: explicit unsafe-inline.
  // Match the script-src directive specifically; ignore style-src.
  const scriptSrcMatch = csp.match(/script-src[^;]*/);
  if (scriptSrcMatch) {
    expect(scriptSrcMatch[0]).not.toContain("'unsafe-inline'");
  }
  // Defence in depth: ``default-src`` shouldn't either.
  const defaultSrcMatch = csp.match(/default-src[^;]*/);
  if (defaultSrcMatch) {
    expect(defaultSrcMatch[0]).not.toContain("'unsafe-inline'");
  }
});

test("CSP includes a frame-ancestors directive @nginx", async ({ analystApi }) => {
  const res = await analystApi.ctx.get("/");
  const csp = (res.headers()["content-security-policy"] ?? "").toLowerCase();
  // ``frame-ancestors`` is the modern equivalent of X-Frame-Options
  // and must be present alongside it for defence in depth.
  expect(csp).toMatch(/frame-ancestors/);
});
