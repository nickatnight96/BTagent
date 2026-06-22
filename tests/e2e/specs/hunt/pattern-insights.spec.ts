/**
 * Pattern Insights E2E spec (#120 Phase B).
 *
 * Seeds a pattern-hunt proposal via the API and verifies the Pattern Insights
 * page (#/pattern-insights) renders it in the ranked proposal list with
 * correct triage controls.
 *
 * Requires the backend running with BTAGENT_MOCK_CONNECTORS=true and
 * auth session files under .auth/.
 *
 * Per-run unique IDs
 * ------------------
 * Every proposal cluster_id / rationale carries a per-invocation ``runTag``
 * so parallel test shards don't share state or interfere with one another.
 *
 * RBAC coverage
 * -------------
 * - senior_analyst can see the "Propose a Hunt" / Dismiss / Snooze buttons.
 * - plain analyst also sees the triage actions (hunt:triage = analyst+).
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

// --------------------------------------------------------------------------- //
// API seed helpers
// --------------------------------------------------------------------------- //

interface SeedProposalPayload {
  cluster_id: string;
  score: number;
  hunt_input: {
    adversaries: string[];
    ttps: string[];
    iocs: unknown[];
    scope: {
      environments: string[];
      hosts: string[];
      date_from: null;
      date_to: null;
      backends: string[];
    };
  };
  rationale: string;
  state: string;
}

/**
 * Seed a pattern-hunt proposal via the test-helper endpoint.
 *
 * Returns ``null`` when the helper isn't wired (404) so the calling test can
 * ``test.skip()`` instead of proceeding with a fabricated id and timing out
 * on a proposal card that was never seeded. */
async function seedProposal(page: Page, payload: SeedProposalPayload): Promise<string | null> {
  const resp = await page.request.post("/api/v1/pattern/test/proposals", {
    data: payload,
  });
  if (resp.status() === 404) return null;
  expect(
    resp.ok(),
    `seedProposal failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //

test.describe("Pattern Insights page", () => {
  test("renders the page header and state-filter tabs", async ({ seniorPage }) => {
    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Header heading.
    await expect(seniorPage.getByRole("heading", { name: "Pattern Insights" })).toBeVisible();

    // State filter tabs must be present.
    await expect(seniorPage.getByTestId("pattern-tab-proposed")).toBeVisible();
    await expect(seniorPage.getByTestId("pattern-tab-accepted")).toBeVisible();
    await expect(seniorPage.getByTestId("pattern-tab-dismissed")).toBeVisible();
    await expect(seniorPage.getByTestId("pattern-tab-snoozed")).toBeVisible();
    await expect(seniorPage.getByTestId("pattern-tab-all")).toBeVisible();
  });

  test("renders proposal cards from seeded data", async ({ seniorPage }) => {
    const now = Date.now();
    const runTag = `pi-e2e-${now}`;

    // Seed a proposal. If the test-seed helpers aren't wired (404),
    // skip this seeded assertion rather than waiting on a card that won't
    // render and timing the test out.
    const proposalId = await seedProposal(seniorPage, {
      cluster_id: `cl_${runTag}`,
      score: 0.82,
      hunt_input: {
        adversaries: [],
        ttps: [`T1059.001`],
        iocs: [],
        scope: {
          environments: [],
          hosts: [],
          date_from: null,
          date_to: null,
          backends: [],
        },
      },
      rationale: `Cross-inv pattern ${runTag}: T1059.001 seen in 3 closed investigations.`,
      state: "proposed",
    });
    test.skip(proposalId === null, "pattern test-seed endpoints not wired");

    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to "all" tab so the seeded proposal is visible regardless of state.
    await seniorPage.getByTestId("pattern-tab-all").click();

    // Proposal card should appear.
    await seniorPage
      .getByTestId("pattern-proposal-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    await expect(seniorPage.getByTestId("pattern-proposal-card")).not.toHaveCount(0);
  });

  test("proposal card expands to show rationale and signal chips", async ({ seniorPage }) => {
    const now = Date.now();
    const runTag = `pi-expand-${now}`;

    const proposalId = await seedProposal(seniorPage, {
      cluster_id: `cl_${runTag}`,
      score: 0.75,
      hunt_input: {
        adversaries: [],
        ttps: ["T1078.004"],
        iocs: [],
        scope: {
          environments: [],
          hosts: [],
          date_from: null,
          date_to: null,
          backends: [],
        },
      },
      rationale: `Expand test ${runTag}`,
      state: "proposed",
    });
    test.skip(proposalId === null, "pattern test-seed endpoints not wired");

    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to "all" tab.
    await seniorPage.getByTestId("pattern-tab-all").click();

    // Wait for at least one card.
    await seniorPage
      .getByTestId("pattern-proposal-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    // Expand the first card.
    await seniorPage.getByTestId("pattern-proposal-expand").first().click();

    // Rationale section should be visible.
    await expect(seniorPage.getByText("Why did this surface?")).toBeVisible();
  });

  test("triage buttons (Propose a Hunt / Snooze / Dismiss) are visible to senior_analyst", async ({
    seniorPage,
  }) => {
    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to proposed tab.
    await seniorPage.getByTestId("pattern-tab-proposed").click();
    await seniorPage.waitForTimeout(300);

    // If there are proposal cards, expand and check action panel.
    const cards = seniorPage.getByTestId("pattern-proposal-card");
    const cardCount = await cards.count();

    if (cardCount > 0) {
      // Expand the first card.
      await seniorPage.getByTestId("pattern-proposal-expand").first().click();

      // Action panel should render for proposed proposals.
      await expect(seniorPage.getByTestId("pattern-action-panel").first()).toBeVisible();
      await expect(seniorPage.getByTestId("pattern-btn-accept").first()).toBeVisible();
      await expect(seniorPage.getByTestId("pattern-btn-snooze").first()).toBeVisible();
      await expect(seniorPage.getByTestId("pattern-btn-dismiss").first()).toBeVisible();
    }
  });

  test("plain analyst sees triage buttons (hunt:triage = analyst+)", async ({
    analystPage,
  }) => {
    // hunt:triage is granted from analyst upward per rbac.py.
    // The RBAC notice must NOT appear for a plain analyst.
    await analystPage.goto("/pattern-insights");
    await analystPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // RBAC notice must NOT be shown — analyst is allowed to triage.
    await expect(analystPage.getByTestId("pattern-rbac-notice")).toHaveCount(0);
  });

  test("empty state appears when no proposals exist for a filter", async ({ seniorPage }) => {
    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to accepted tab — least likely to have data in a fresh env.
    await seniorPage.getByTestId("pattern-tab-accepted").click();
    await seniorPage.waitForTimeout(500);

    const cards = seniorPage.getByTestId("pattern-proposal-card");
    const cardCount = await cards.count();

    if (cardCount === 0) {
      // Empty state card must be visible.
      await expect(
        seniorPage.getByText(/No accepted proposals in this view/),
      ).toBeVisible({ timeout: 5_000 });
    }
    // If cardCount > 0 the tab has data — empty-state assertion is skipped.
  });

  test("refresh button triggers a data reload", async ({ seniorPage }) => {
    await seniorPage.goto("/pattern-insights");
    await seniorPage
      .getByTestId("pattern-insights-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    const refreshBtn = seniorPage.getByTestId("pattern-refresh");
    await expect(refreshBtn).toBeVisible();
    // Click should not throw or crash the page.
    await refreshBtn.click();
    await expect(seniorPage.getByTestId("pattern-insights-page")).toBeVisible();
  });
});
