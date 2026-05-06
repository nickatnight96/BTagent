/**
 * Playwright configuration for BTagent E2E tests.
 *
 * Two execution modes — controlled by env:
 *
 *   E2E_MODE=local      Spins up frontend + backend automatically via the
 *                       webServer entries below. Assumes Postgres + Redis
 *                       are already running (e.g. via ``make dev`` or the
 *                       infra Docker Compose).
 *
 *   E2E_MODE=ci         Skips webServer startup — CI brings up the full
 *                       stack itself (see .github/workflows/ci.yml e2e
 *                       job, Sprint H). The tests connect to whatever
 *                       BASE_URL points at.
 *
 * BASE_URL default is ``http://localhost:5173`` (Vite dev). CI overrides
 * to the served bundle URL.
 */
import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:5173";
const API_URL = process.env.E2E_API_URL ?? "http://localhost:8000";
const MODE = process.env.E2E_MODE ?? "local";
const IS_CI = !!process.env.CI;

export default defineConfig({
  testDir: "./specs",
  outputDir: "./test-results",

  // Whole suite cap. Long enough for the slowest workspace setups
  // (orchestrator boot, WebSocket reconnect, agent eval) but short
  // enough that a hung test fails the run instead of dragging it.
  timeout: 60_000,
  expect: { timeout: 10_000 },

  // CI runs the full matrix sequentially-per-worker so trace files
  // don't fight for disk; local dev parallelises by default.
  fullyParallel: !IS_CI,
  workers: IS_CI ? 4 : undefined,

  // Sets a max-failures cap so a single broken commit doesn't
  // exhaust runner minutes by retrying every test.
  forbidOnly: IS_CI,
  retries: IS_CI ? 2 : 0,
  maxFailures: IS_CI ? 30 : undefined,

  reporter: IS_CI
    ? [
        ["html", { outputFolder: "playwright-report", open: "never" }],
        ["junit", { outputFile: "test-results/junit.xml" }],
        ["github"],
      ]
    : [["html", { open: "on-failure" }], ["list"]],

  use: {
    baseURL: BASE_URL,
    // ``on-first-retry`` so passes don't carry the trace overhead but
    // any flake gives us full forensics (network, DOM snapshots, console).
    trace: "on-first-retry",
    video: IS_CI ? "retain-on-failure" : "on-first-retry",
    screenshot: "only-on-failure",
    // No mouse-eased waits — every test must rely on explicit awaits
    // on the locator's resolved state.
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    // The frontend serves cookies on Secure=true in prod but the test
    // harness uses http://, so let the BTAGENT_COOKIE_INSECURE override
    // upstream do its job. Leaving ``ignoreHTTPSErrors=false`` here on
    // purpose so we catch any accidental https://prod URL leak.
    extraHTTPHeaders: {
      "x-e2e-test": "1",
    },
  },

  projects: [
    {
      name: "setup",
      testMatch: /.*\.setup\.ts/,
    },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
    },
    // The full multi-browser matrix — Sprint J targets these. Disabled
    // in default ``npm test`` runs to keep CI fast; opt in via
    // ``npm run test:firefox`` etc.
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
      dependencies: ["setup"],
      // Disabled by default in CI: enabling adds ~2x runtime. Run via
      // ``--project=firefox`` explicitly.
      grep: /@cross-browser/,
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
      dependencies: ["setup"],
      grep: /@cross-browser/,
    },
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 7"] },
      dependencies: ["setup"],
      // Mobile-specific subset — login + investigation list at a
      // minimum. Tagged with ``@mobile`` so authors can opt in.
      grep: /@mobile/,
    },
  ],

  // Local-only auto-server. CI's ``e2e`` job (Sprint H) brings up the
  // full Docker stack itself before invoking ``npx playwright test``.
  webServer: MODE === "local"
    ? [
        {
          command: "cd ../../frontend && npm run dev -- --port 5173",
          url: "http://localhost:5173",
          reuseExistingServer: true,
          timeout: 60_000,
          stdout: "ignore",
          stderr: "pipe",
        },
        {
          // Backend assumed up via ``make dev``; this is a noop probe.
          // If you want Playwright to start the backend too, replace
          // with the full uvicorn invocation.
          command: `node -e "require('http').get('${API_URL}/api/v1/health', r => r.statusCode === 200 ? process.exit(0) : process.exit(1)).on('error', () => process.exit(1))"`,
          url: `${API_URL}/api/v1/health`,
          reuseExistingServer: true,
          timeout: 5_000,
        },
      ]
    : undefined,
});
