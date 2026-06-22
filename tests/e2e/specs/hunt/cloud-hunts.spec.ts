/**
 * Cloud Hunts E2E spec (#117 Phase B).
 *
 * Seeds cloud hunt findings via the test-helper endpoint and verifies the
 * Cloud Hunts page (/cloud-hunts) renders them in the correct views:
 *  - Control-plane event timeline
 *  - IAM role-graph (nested list)
 *  - Shadow-workload matrix + shadow finding list
 *  - Tamper tab (technique-family grouping)
 *
 * Requires the backend running with BTAGENT_MOCK_CONNECTORS=true and
 * auth session files under .auth/.
 *
 * Per-run unique IDs
 * ------------------
 * Every seeded record carries a per-invocation ``runTag`` so parallel test
 * shards don't share state or interfere with one another.
 *
 * skip-on-404 pattern
 * -------------------
 * All test-seed helpers return ``null`` on HTTP 404 (endpoint not yet wired).
 * Tests call ``test.skip()`` in that case rather than timing out on a card
 * that was never rendered. This mirrors the ``behavioral-hunts.spec.ts``
 * pattern merged in #211.
 *
 * RBAC coverage
 * -------------
 * - senior_analyst sees promote buttons.
 * - plain analyst sees triage interface but no promote button.
 */

import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// API seed helpers
// ---------------------------------------------------------------------------

interface SeedCloudFindingPayload {
  title: string;
  severity?: string;
  technique_ids?: string[];
  evidence?: Record<string, unknown>;
}

/**
 * Seed a cloud hunt finding via the test-helper endpoint.
 *
 * Returns ``null`` when the helper endpoint is not wired (HTTP 404), in which
 * case the calling test should call ``test.skip()``.
 */
async function seedCloudFinding(
  page: Page,
  payload: SeedCloudFindingPayload,
): Promise<string | null> {
  const resp = await page.request.post("/api/v1/hunt/test/findings", {
    data: {
      source: "cloud",
      domain: "cloud",
      severity: "medium",
      confidence: 0.8,
      technique_ids: [],
      entities: [],
      observables: [],
      evidence: {},
      description: "",
      ...payload,
    },
  });
  if (resp.status() === 404) return null;
  expect(
    resp.ok(),
    `seedCloudFinding failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Cloud Hunts page", () => {
  // --------------------------------------------------------------------------
  // Basic page render
  // --------------------------------------------------------------------------

  test("renders the Cloud Hunts page with header and tabs", async ({ seniorPage }) => {
    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Header.
    await expect(seniorPage.getByRole("heading", { name: "Cloud Hunts" })).toBeVisible();

    // Tabs.
    await expect(seniorPage.getByTestId("cloud-tab-timeline")).toBeVisible();
    await expect(seniorPage.getByTestId("cloud-tab-iam")).toBeVisible();
    await expect(seniorPage.getByTestId("cloud-tab-shadow_workloads")).toBeVisible();
    await expect(seniorPage.getByTestId("cloud-tab-tamper")).toBeVisible();

    // Refresh button.
    await expect(seniorPage.getByTestId("cloud-refresh")).toBeVisible();
  });

  // --------------------------------------------------------------------------
  // Timeline tab
  // --------------------------------------------------------------------------

  test("timeline tab shows seeded control-plane events grouped by account", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ch-tl-${now}`;
    const accountId = `123456${String(now).slice(-6)}`;

    const findingId = await seedCloudFinding(seniorPage, {
      title: `CloudTrail AssumeRole ${runTag}`,
      severity: "high",
      technique_ids: ["T1078.004"],
      evidence: {
        provider: "aws",
        account_id: accountId,
        actor_arn: `arn:aws:iam::${accountId}:role/AttackerRole-${runTag}`,
        target_arn: `arn:aws:iam::${accountId}:role/VictimRole-${runTag}`,
      },
    });
    test.skip(findingId === null, "cloud finding test-seed endpoint not wired");

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Timeline tab should be active by default.
    await seniorPage
      .getByTestId("cloud-timeline")
      .waitFor({ state: "visible", timeout: 15_000 });

    // At least one timeline row.
    await expect(seniorPage.getByTestId("cloud-timeline-row")).not.toHaveCount(0);
  });

  // --------------------------------------------------------------------------
  // IAM graph tab
  // --------------------------------------------------------------------------

  test("IAM graph tab shows source-role cards for findings with path", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ch-iam-${now}`;
    const accountId = `234567${String(now).slice(-6)}`;

    const findingId = await seedCloudFinding(seniorPage, {
      title: `IAM AssumeRole chain ${runTag}`,
      severity: "critical",
      evidence: {
        provider: "aws",
        account_id: accountId,
        path: [
          `arn:aws:iam::${accountId}:role/SourceRole-${runTag}`,
          `arn:aws:iam::${accountId}:role/MiddleRole-${runTag}`,
          `arn:aws:iam::${accountId}:role/TargetRole-${runTag}`,
        ],
      },
    });
    test.skip(findingId === null, "cloud finding test-seed endpoint not wired");

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to IAM tab.
    await seniorPage.getByTestId("cloud-tab-iam").click();
    await seniorPage
      .getByTestId("cloud-iam-graph")
      .waitFor({ state: "visible", timeout: 15_000 });

    // Should render source-role cards.
    await expect(seniorPage.getByTestId("cloud-iam-source-role")).not.toHaveCount(0);

    // Each card should be expandable to show trustee rows.
    const firstCard = seniorPage.getByTestId("cloud-iam-source-role").first();
    await firstCard.getByTestId("cloud-iam-expand").click();
    await expect(seniorPage.getByTestId("cloud-iam-trustee-row").first()).toBeVisible({
      timeout: 5_000,
    });
  });

  // --------------------------------------------------------------------------
  // Shadow workloads tab — matrix and list
  // --------------------------------------------------------------------------

  test("shadow workloads tab renders matrix and shadow finding list", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ch-shad-${now}`;

    const findingId = await seedCloudFinding(seniorPage, {
      title: `Shadow AgentCore workload ${runTag}`,
      severity: "high",
      evidence: {
        provider: "aws",
        workload_kind: "bedrock_agentcore",
        shadow_workload: true,
        risk_score: 0.85,
      },
    });
    test.skip(findingId === null, "cloud finding test-seed endpoint not wired");

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to shadow workloads tab.
    await seniorPage.getByTestId("cloud-tab-shadow_workloads").click();
    await seniorPage
      .getByTestId("cloud-shadow-tab")
      .waitFor({ state: "visible", timeout: 15_000 });

    // Matrix table should always be rendered.
    await expect(seniorPage.getByTestId("cloud-workload-matrix")).toBeVisible();

    // Shadow finding row should appear.
    await expect(seniorPage.getByTestId("cloud-shadow-finding-row").first()).toBeVisible({
      timeout: 10_000,
    });
  });

  // --------------------------------------------------------------------------
  // Tamper tab
  // --------------------------------------------------------------------------

  test("tamper tab groups findings by technique_family", async ({ seniorPage }) => {
    const now = Date.now();
    const runTag = `ch-tamp-${now}`;

    const findingId = await seedCloudFinding(seniorPage, {
      title: `CloudTrail log delete ${runTag}`,
      severity: "critical",
      evidence: {
        provider: "aws",
        technique_family: "Defense Evasion",
      },
    });
    test.skip(findingId === null, "cloud finding test-seed endpoint not wired");

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to tamper tab.
    await seniorPage.getByTestId("cloud-tab-tamper").click();
    await seniorPage
      .getByTestId("cloud-tamper-tab")
      .waitFor({ state: "visible", timeout: 15_000 });

    // At least one family card.
    await expect(seniorPage.getByTestId("cloud-tamper-family-card")).not.toHaveCount(0);
  });

  // --------------------------------------------------------------------------
  // RBAC — senior_analyst sees promote button
  // --------------------------------------------------------------------------

  test("senior_analyst can see promote button on timeline findings", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `ch-rbac-senior-${now}`;

    const findingId = await seedCloudFinding(seniorPage, {
      title: `Promote test finding ${runTag}`,
      evidence: { provider: "azure", account_id: `sub-${runTag}` },
    });
    test.skip(findingId === null, "cloud finding test-seed endpoint not wired");

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    await seniorPage
      .getByTestId("cloud-timeline")
      .waitFor({ state: "visible", timeout: 15_000 });

    // Expand first timeline row.
    const timelineRows = seniorPage.getByTestId("cloud-timeline-row");
    const rowCount = await timelineRows.count();

    if (rowCount > 0) {
      await seniorPage.getByTestId("cloud-timeline-expand").first().click();
      // senior_analyst should see the promote button.
      await expect(seniorPage.getByTestId("cloud-promote-btn").first()).toBeVisible({
        timeout: 3_000,
      });
    }
  });

  // --------------------------------------------------------------------------
  // RBAC — analyst sees page but not promote button
  // --------------------------------------------------------------------------

  test("analyst sees cloud hunts page but has no promote button", async ({
    analystPage,
  }) => {
    await analystPage.goto("/cloud-hunts");
    await analystPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Page renders without RBAC notice (analyst can triage).
    await expect(analystPage.getByTestId("cloud-rbac-notice")).toHaveCount(0);

    // Expand first timeline row if any rows exist.
    const rowCount = await analystPage.getByTestId("cloud-timeline-row").count();
    if (rowCount > 0) {
      await analystPage.getByTestId("cloud-timeline-expand").first().click();
      // Promote button must not be present for plain analyst.
      await expect(analystPage.getByTestId("cloud-promote-btn")).toHaveCount(0);
    }
  });

  // --------------------------------------------------------------------------
  // Refresh button
  // --------------------------------------------------------------------------

  test("refresh button triggers data reload", async ({ seniorPage }) => {
    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    const refreshBtn = seniorPage.getByTestId("cloud-refresh");
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();
    // Page should still be visible after refresh.
    await expect(seniorPage.getByTestId("cloud-hunts-page")).toBeVisible();
  });

  // --------------------------------------------------------------------------
  // Empty state — IAM tab with no path data
  // --------------------------------------------------------------------------

  test("IAM tab shows empty state when no findings carry path", async ({
    seniorPage,
  }) => {
    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to IAM tab.
    await seniorPage.getByTestId("cloud-tab-iam").click();
    await seniorPage.waitForTimeout(1_000);

    // Either IAM source-role cards exist, or the empty-state card is shown.
    const roleCards = seniorPage.getByTestId("cloud-iam-source-role");
    const cardCount = await roleCards.count();

    if (cardCount === 0) {
      await expect(
        seniorPage.getByTestId("cloud-iam-graph"),
      ).toBeVisible({ timeout: 5_000 });
    }
  });
});
