/**
 * Auth fixtures — one logged-in browser context per persona.
 *
 * The setup project (``auth.setup.ts``) runs once per test run and
 * stashes ``storageState`` files under ``.auth/`` for each persona. The
 * fixtures below load the appropriate state into a fresh browser
 * context, so a test asking for ``analystPage`` gets an already-logged-in
 * page without paying the login round-trip.
 *
 * **Why fixtures-over-projects:** Playwright's project mechanism
 * supports per-project ``storageState``, but using projects to encode
 * persona means a test that wants two personas (e.g. cross-org IDOR)
 * has to spin up two Playwright workers and exchange data. Fixtures
 * let one test request multiple persona contexts cheaply.
 */
import { test as base, type BrowserContext, type Page } from "@playwright/test";
import { BTAgentApiClient } from "./api-client";

export type Persona = "admin" | "analyst" | "senior";

const STATE_FILE: Record<Persona, string> = {
  admin: ".auth/admin.json",
  analyst: ".auth/analyst.json",
  senior: ".auth/senior.json",
};

interface AuthFixtures {
  /** API client logged in via the cookie transport (matches the SPA). */
  api: BTAgentApiClient;
  /** API client logged in as admin. */
  adminApi: BTAgentApiClient;
  /** API client logged in as analyst1. */
  analystApi: BTAgentApiClient;
  /** API client logged in as senior1. */
  seniorApi: BTAgentApiClient;
  /** Pre-authenticated page for the admin persona. */
  adminPage: Page;
  /** Pre-authenticated page for the analyst persona. */
  analystPage: Page;
  /** Pre-authenticated page for the senior_analyst persona. */
  seniorPage: Page;
  /** Anonymous page (no auth). Use for login + auth-failure tests. */
  anonymousPage: Page;
}

async function pageForPersona(
  browser: import("@playwright/test").Browser,
  persona: Persona,
): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext({
    storageState: STATE_FILE[persona],
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
  const page = await ctx.newPage();
  return { ctx, page };
}

export const test = base.extend<AuthFixtures>({
  // -- API clients ----------------------------------------------------

  api: async ({}, use) => {
    const client = await BTAgentApiClient.newAnonymous();
    await use(client);
    await client.dispose();
  },

  adminApi: async ({}, use) => {
    const client = await BTAgentApiClient.loginWithCookie({
      username: "admin",
      password: "admin",
    });
    await use(client);
    await client.dispose();
  },

  analystApi: async ({}, use) => {
    const client = await BTAgentApiClient.loginWithCookie({
      username: "analyst1",
      password: "analyst1",
    });
    await use(client);
    await client.dispose();
  },

  seniorApi: async ({}, use) => {
    const client = await BTAgentApiClient.loginWithCookie({
      username: "senior1",
      password: "senior1",
    });
    await use(client);
    await client.dispose();
  },

  // -- Browser pages --------------------------------------------------

  adminPage: async ({ browser }, use) => {
    const { ctx, page } = await pageForPersona(browser, "admin");
    await use(page);
    await ctx.close();
  },

  analystPage: async ({ browser }, use) => {
    const { ctx, page } = await pageForPersona(browser, "analyst");
    await use(page);
    await ctx.close();
  },

  seniorPage: async ({ browser }, use) => {
    const { ctx, page } = await pageForPersona(browser, "senior");
    await use(page);
    await ctx.close();
  },

  anonymousPage: async ({ browser }, use) => {
    const ctx = await browser.newContext({
      storageState: undefined,
      extraHTTPHeaders: { "x-e2e-test": "1" },
    });
    const page = await ctx.newPage();
    await use(page);
    await ctx.close();
  },
});

export { expect } from "@playwright/test";
