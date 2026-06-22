/**
 * Identity Hunts E2E spec (#116 Phase B).
 *
 * Verifies the Identity Hunts page (/identity-hunts) renders the per-principal
 * token-lifecycle timeline, anomalous-consent panel, and OAuth-grant table
 * using identity HuntFindings (domain=identity).
 *
 * Seeding strategy
 * ----------------
 * Identity findings are standard HuntFindings with domain=identity.  This
 * spec attempts to seed via the existing hunt test-helper endpoint
 * ``POST /api/v1/hunt/test/findings`` (if it's wired).  If the helper returns
 * 404 (not wired in this environment) the relevant assertions are skipped
 * gracefully — the page-structure and RBAC tests still run.
 *
 * Per-run unique IDs
 * ------------------
 * Every seeded record carries a per-invocation ``runTag`` so parallel test
 * shards don't share state.
 *
 * RBAC coverage
 * -------------
 * - senior_analyst: full triage (suppress + promote) access; no RBAC notice.
 * - plain analyst:  triage (suppress) access; no promote button shown.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

// --------------------------------------------------------------------------- //
// Seed helper
// --------------------------------------------------------------------------- //

interface SeedFindingPayload {
  title: string;
  description?: string;
  severity: string;
  confidence?: number;
  domain: string;
  source: string;
  technique_ids?: string[];
  entities?: Array<{ kind: string; value: string }>;
  evidence?: Record<string, unknown>;
}

/**
 * Seed an identity HuntFinding via the hunt test-helper endpoint.
 *
 * Returns ``null`` when the helper isn't wired (404) so calling tests can
 * ``test.skip()`` instead of waiting on a card that will never render.
 *
 * Pattern mirrors ``behavioral-hunts.spec.ts`` (merged #211).
 */
async function seedIdentityFinding(
  page: Page,
  payload: SeedFindingPayload,
): Promise<string | null> {
  const resp = await page.request.post("/api/v1/hunt/test/findings", {
    data: {
      confidence: 0.8,
      technique_ids: [],
      entities: [],
      evidence: {},
      ...payload,
    },
  });
  if (resp.status() === 404) return null;
  expect(
    resp.ok(),
    `seedIdentityFinding failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //

test.describe("Identity Hunts page", () => {
  test("page structure is visible — header, tabs, nav link", async ({ seniorPage }) => {
    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Heading visible.
    await expect(seniorPage.getByRole("heading", { name: "Identity Hunts" })).toBeVisible();

    // State filter tabs present.
    await expect(seniorPage.getByTestId("identity-tab-active")).toBeVisible();
    await expect(seniorPage.getByTestId("identity-tab-suppressed")).toBeVisible();
    await expect(seniorPage.getByTestId("identity-tab-promoted")).toBeVisible();

    // Refresh button present.
    await expect(seniorPage.getByTestId("identity-refresh")).toBeVisible();
  });

  test("sidebar nav link navigates to /identity-hunts", async ({ seniorPage }) => {
    await seniorPage.goto("/");
    await seniorPage.getByTestId("nav-identity-hunts-link").click();
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });
    expect(seniorPage.url()).toContain("/identity-hunts");
  });

  test("renders per-principal card from seeded identity finding", async ({ seniorPage }) => {
    const now = Date.now();
    const runTag = `ih-e2e-${now}`;
    const principalId = `alice-${runTag}@corp.test`;

    const findingId = await seedIdentityFinding(seniorPage, {
      title: `Token replay detected — ${runTag}`,
      severity: "high",
      domain: "identity",
      source: "identity",
      technique_ids: ["T1550.001"],
      entities: [{ kind: "user", value: principalId }],
      evidence: {
        principal_id: principalId,
        cred_type: "access_token",
        distinct_asns: 3,
        asns: ["AS15169", "AS16509", "AS8075"],
        provider: "okta",
      },
    });
    test.skip(findingId === null, "hunt test-seed endpoint not wired");

    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // At least one principal card should appear.
    await seniorPage
      .getByTestId("identity-principal-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    await expect(seniorPage.getByTestId("identity-principal-card")).not.toHaveCount(0);
  });

  test("expanding a principal card shows the token-lifecycle timeline", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ih-timeline-${now}`;
    const principalId = `bob-${runTag}@corp.test`;

    const findingId = await seedIdentityFinding(seniorPage, {
      title: `MFA fatigue — ${runTag}`,
      severity: "medium",
      domain: "identity",
      source: "identity",
      technique_ids: ["T1621"],
      entities: [{ kind: "user", value: principalId }],
      evidence: {
        principal_id: principalId,
        mfa_push_count: 12,
        mfa_deny_count: 11,
        window_seconds: 300,
        provider: "entra",
      },
    });
    test.skip(findingId === null, "hunt test-seed endpoint not wired");

    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-principal-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    // Expand the first principal card.
    await seniorPage.getByTestId("identity-principal-expand").first().click();

    // Timeline should appear.
    await seniorPage
      .getByTestId("identity-timeline")
      .first()
      .waitFor({ state: "visible", timeout: 5_000 });

    // At least one timeline entry.
    await expect(seniorPage.getByTestId("identity-timeline-entry")).not.toHaveCount(0);
  });

  test("anomalous-consent panel appears for T1078.004 findings", async ({ seniorPage }) => {
    const now = Date.now();
    const runTag = `ih-consent-${now}`;
    const principalId = `svc-${runTag}@corp.test`;

    const findingId = await seedIdentityFinding(seniorPage, {
      title: `OAuth consent grant — ${runTag}`,
      severity: "high",
      domain: "identity",
      source: "identity",
      technique_ids: ["T1078.004"],
      entities: [{ kind: "service_principal", value: principalId }],
      evidence: {
        principal_id: principalId,
        app_id: `app-${runTag}`,
        app_display_name: `E2E OAuth App ${runTag}`,
        scopes: ["Mail.ReadWrite", "offline_access"],
        consent_type: "admin",
        provider: "entra",
      },
    });
    test.skip(findingId === null, "hunt test-seed endpoint not wired");

    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Consent panel should be visible when T1078.004 findings exist.
    await seniorPage
      .getByTestId("identity-consent-panel")
      .waitFor({ state: "visible", timeout: 15_000 });

    await expect(seniorPage.getByTestId("identity-consent-row")).not.toHaveCount(0);
  });

  test("OAuth grant table appears for findings with app_id in evidence", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ih-grant-${now}`;
    const principalId = `user-${runTag}@corp.test`;

    const findingId = await seedIdentityFinding(seniorPage, {
      title: `Dormant app reactivation — ${runTag}`,
      severity: "high",
      domain: "identity",
      source: "identity",
      technique_ids: ["T1078.004"],
      entities: [{ kind: "user", value: principalId }],
      evidence: {
        principal_id: principalId,
        app_id: `dormant-app-${runTag}`,
        app_display_name: `Dormant App ${runTag}`,
        scopes: ["Files.ReadWrite.All"],
        consent_type: "pre_authorized",
        dormant_days: 95,
        previously_revoked: true,
      },
    });
    test.skip(findingId === null, "hunt test-seed endpoint not wired");

    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Wait for findings to load and grant table to render.
    await seniorPage
      .getByTestId("identity-grant-table")
      .waitFor({ state: "visible", timeout: 15_000 });

    await expect(seniorPage.getByTestId("identity-grant-row")).not.toHaveCount(0);
  });

  test("senior_analyst sees suppress and promote buttons", async ({ seniorPage }) => {
    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Senior should not see RBAC notice.
    await expect(seniorPage.getByTestId("identity-rbac-notice")).toHaveCount(0);

    // If any principal cards are present, expand one and check buttons.
    const cards = seniorPage.getByTestId("identity-principal-card");
    const cardCount = await cards.count();

    if (cardCount > 0) {
      await seniorPage.getByTestId("identity-principal-expand").first().click();

      const entries = seniorPage.getByTestId("identity-timeline-entry");
      const entryCount = await entries.count();
      if (entryCount > 0) {
        // Suppress button should be visible for senior.
        await expect(
          seniorPage.getByTestId("identity-suppress-btn").first(),
        ).toBeVisible();
        // Promote button should be visible for senior.
        await expect(
          seniorPage.getByTestId("identity-promote-btn").first(),
        ).toBeVisible();
      }
    }
  });

  test("plain analyst can triage but promote button is not shown", async ({ analystPage }) => {
    await analystPage.goto("/identity-hunts");
    await analystPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Analyst has hunt:triage; no RBAC notice should appear.
    // (Promote is hunt:promote which is senior+, so promote buttons are absent.)
    // The RBAC notice in this page is only for users below analyst.
    const rbacNotice = analystPage.getByTestId("identity-rbac-notice");
    await expect(rbacNotice).toHaveCount(0);

    // Expand if any cards are available.
    const cards = analystPage.getByTestId("identity-principal-card");
    const cardCount = await cards.count();
    if (cardCount > 0) {
      await analystPage.getByTestId("identity-principal-expand").first().click();
      const entries = analystPage.getByTestId("identity-timeline-entry");
      const entryCount = await entries.count();
      if (entryCount > 0) {
        // Promote buttons should NOT be rendered for analyst.
        await expect(analystPage.getByTestId("identity-promote-btn")).toHaveCount(0);
      }
    }
  });

  test("empty state renders when no identity findings exist", async ({ seniorPage }) => {
    // Navigate to promoted tab — least likely to have data.
    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await seniorPage.getByTestId("identity-tab-promoted").click();
    await seniorPage.waitForTimeout(500);

    const cards = seniorPage.getByTestId("identity-principal-card");
    const cardCount = await cards.count();

    if (cardCount === 0) {
      // Empty state must be visible.
      await expect(
        seniorPage.getByText(/No promoted identity findings/),
      ).toBeVisible({ timeout: 5_000 });
    }
    // If cardCount > 0 there's data — skip the assertion.
  });

  test("refresh button triggers a data reload without error", async ({ seniorPage }) => {
    await seniorPage.goto("/identity-hunts");
    await seniorPage
      .getByTestId("identity-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    const refreshBtn = seniorPage.getByTestId("identity-refresh");
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    await expect(seniorPage.getByTestId("identity-hunts-page")).toBeVisible();
  });
});
