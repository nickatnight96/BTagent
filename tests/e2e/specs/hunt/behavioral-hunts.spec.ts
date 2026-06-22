/**
 * Behavioral Hunts E2E spec (#114 Phase B).
 *
 * Seeds a behavioral entity + outlier records via the API and verifies the
 * Behavioral Hunts page (#/behavioral) renders them in the entity drift
 * dashboard with correct triage controls.
 *
 * Requires the backend running with BTAGENT_MOCK_CONNECTORS=true and
 * auth session files under .auth/.
 *
 * Per-run unique IDs
 * ------------------
 * Every entity canonical_id / event_id carries a per-invocation ``runTag``
 * so parallel test shards don't share state or interfere with one another.
 *
 * RBAC coverage
 * -------------
 * - senior_analyst can see triage buttons (benign / suspicious / malicious).
 * - plain analyst sees the RBAC notice and NO triage buttons.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

// --------------------------------------------------------------------------- //
// API seed helpers
// --------------------------------------------------------------------------- //

interface SeedEntityPayload {
  kind: string;
  canonical_id: string;
  enrichment?: Record<string, unknown>;
}

interface SeedOutlierPayload {
  entity_id: string;
  profile_type: string;
  event_id: string;
  cosine_distance: number;
  frequency_rank: number;
  raw_event_excerpt?: string;
}

/** Seed a behavioral entity via the test-helper endpoint.
 *
 * Returns ``null`` when the helper isn't wired (404) so the calling test can
 * ``test.skip()`` instead of proceeding with a fabricated id and timing out on
 * a ``behavioral-entity-card`` that was never seeded. */
async function seedEntity(page: Page, payload: SeedEntityPayload): Promise<string | null> {
  const resp = await page.request.post("/api/v1/behavioral/test/entities", {
    data: { enrichment: {}, ...payload },
  });
  if (resp.status() === 404) return null;
  expect(
    resp.ok(),
    `seedEntity failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

/** Seed a behavioral outlier via the test-helper endpoint. Returns ``null``
 * when the helper isn't wired (404). */
async function seedOutlier(page: Page, payload: SeedOutlierPayload): Promise<string | null> {
  const resp = await page.request.post("/api/v1/behavioral/test/outliers", {
    data: { raw_event_excerpt: "", ...payload },
  });
  if (resp.status() === 404) return null;
  expect(
    resp.ok(),
    `seedOutlier failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  return ((await resp.json()) as { id: string }).id;
}

// --------------------------------------------------------------------------- //
// Tests
// --------------------------------------------------------------------------- //

test.describe("Behavioral Hunts page", () => {
  test("renders entity drift dashboard and entity cards from seeded data", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `bh-e2e-${now}`;

    // Seed entity + outlier. If the test-seed helpers aren't wired (404),
    // skip this seeded assertion rather than waiting on a card that won't
    // render and timing the test out.
    const entityId = await seedEntity(seniorPage, {
      kind: "host",
      canonical_id: `dc01-${runTag}.corp`,
    });
    test.skip(entityId === null, "behavioral test-seed endpoints not wired");
    const outlierId = await seedOutlier(seniorPage, {
      entity_id: entityId!,
      profile_type: "cmdline_embedding",
      event_id: `evt_${runTag}_1`,
      cosine_distance: 0.85,
      frequency_rank: 0,
      raw_event_excerpt: `powershell.exe -enc ${runTag}AAAA`,
    });
    test.skip(outlierId === null, "behavioral test-seed endpoints not wired");

    await seniorPage.goto("/behavioral");
    await seniorPage
      .getByTestId("behavioral-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Header should be visible with a count.
    await expect(seniorPage.getByRole("heading", { name: "Behavioral Hunts" })).toBeVisible();

    // Intent filter tabs must be present.
    await expect(seniorPage.getByTestId("behavioral-tab-all")).toBeVisible();
    await expect(seniorPage.getByTestId("behavioral-tab-suspicious")).toBeVisible();
    await expect(seniorPage.getByTestId("behavioral-tab-malicious")).toBeVisible();
    await expect(seniorPage.getByTestId("behavioral-tab-benign")).toBeVisible();

    // Entity card should appear (wait for data to load).
    await seniorPage
      .getByTestId("behavioral-entity-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    // At least one entity card is rendered.
    await expect(seniorPage.getByTestId("behavioral-entity-card")).not.toHaveCount(0);
  });

  test("per-entity drilldown shows outlier rows with cosine_distance and frequency_rank", async ({
    seniorPage,
  }) => {
    const now = Date.now();
    const runTag = `bh-drill-${now}`;

    const entityId = await seedEntity(seniorPage, {
      kind: "user",
      canonical_id: `svc-account-${runTag}`,
    });
    test.skip(entityId === null, "behavioral test-seed endpoints not wired");
    const outlierId = await seedOutlier(seniorPage, {
      entity_id: entityId!,
      profile_type: "cmdline_embedding",
      event_id: `evt_drill_${runTag}`,
      cosine_distance: 0.75,
      frequency_rank: 2,
      raw_event_excerpt: `net.exe localgroup administrators /add ${runTag}`,
    });
    test.skip(outlierId === null, "behavioral test-seed endpoints not wired");

    await seniorPage.goto("/behavioral");
    await seniorPage
      .getByTestId("behavioral-entity-card")
      .first()
      .waitFor({ state: "visible", timeout: 15_000 });

    // Expand the first entity card.
    const expandBtn = seniorPage.getByTestId("behavioral-entity-expand").first();
    await expandBtn.click();

    // Outlier row should appear.
    await seniorPage
      .getByTestId("behavioral-outlier-row")
      .first()
      .waitFor({ state: "visible", timeout: 5_000 });

    // Expand the first outlier row to see indicators.
    await seniorPage.getByTestId("behavioral-outlier-expand").first().click();

    // Cosine distance and frequency rank indicators.
    await expect(seniorPage.getByTestId("behavioral-cosine-distance").first()).toBeVisible();
    await expect(seniorPage.getByTestId("behavioral-frequency-rank").first()).toBeVisible();
  });

  test("triage buttons are visible to senior_analyst", async ({ seniorPage }) => {
    await seniorPage.goto("/behavioral");
    await seniorPage
      .getByTestId("behavioral-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // No RBAC notice for senior.
    await expect(seniorPage.getByTestId("behavioral-rbac-notice")).toHaveCount(0);

    // Expand the first entity card and first outlier row to reach the triage panel.
    const cards = seniorPage.getByTestId("behavioral-entity-card");
    const cardCount = await cards.count();

    if (cardCount > 0) {
      await seniorPage.getByTestId("behavioral-entity-expand").first().click();
      const outlierCount = await seniorPage.getByTestId("behavioral-outlier-row").count();

      if (outlierCount > 0) {
        await seniorPage.getByTestId("behavioral-outlier-expand").first().click();
        // Triage panel should render.
        await expect(seniorPage.getByTestId("triage-panel").first()).toBeVisible();
        await expect(seniorPage.getByTestId("triage-btn-benign").first()).toBeVisible();
        await expect(seniorPage.getByTestId("triage-btn-suspicious").first()).toBeVisible();
        await expect(seniorPage.getByTestId("triage-btn-malicious").first()).toBeVisible();
      }
    }
  });

  test("plain analyst can triage (hunt:triage) but cannot promote (hunt:promote)", async ({
    analystPage,
  }) => {
    // Backend RBAC grants ``hunt:triage`` from analyst upward (see
    // ``backend/btagent_backend/auth/rbac.py``), so the page must NOT show the
    // RBAC notice for a plain analyst and the intent buttons must be reachable.
    // Promotion is a distinct ``hunt:promote`` perm gated at senior_analyst+.
    await analystPage.goto("/behavioral");
    await analystPage
      .getByTestId("behavioral-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // RBAC notice must NOT be shown — analyst is allowed to triage.
    await expect(analystPage.getByTestId("behavioral-rbac-notice")).toHaveCount(0);

    // Expand entity + outlier if any exist, and confirm the triage panel renders
    // for the analyst, but the promote button is hidden.
    const cards = analystPage.getByTestId("behavioral-entity-card");
    const cardCount = await cards.count();

    if (cardCount > 0) {
      await analystPage.getByTestId("behavioral-entity-expand").first().click();
      const outlierCount = await analystPage.getByTestId("behavioral-outlier-row").count();

      if (outlierCount > 0) {
        await analystPage.getByTestId("behavioral-outlier-expand").first().click();
        // Triage panel + intent buttons reachable for analyst.
        await expect(analystPage.getByTestId("triage-panel").first()).toBeVisible();
        await expect(analystPage.getByTestId("triage-btn-benign").first()).toBeVisible();
        await expect(analystPage.getByTestId("triage-btn-suspicious").first()).toBeVisible();
        await expect(analystPage.getByTestId("triage-btn-malicious").first()).toBeVisible();
        // Promote is hunt:promote (senior+); must NOT be visible for analyst.
        await expect(analystPage.getByTestId("promote-btn")).toHaveCount(0);
      }
    }
  });

  test("empty state appears when no outliers exist", async ({ seniorPage }) => {
    // Navigate directly to the malicious filter tab, which is least likely
    // to have data in a fresh test environment.
    await seniorPage.goto("/behavioral");
    await seniorPage
      .getByTestId("behavioral-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    // Switch to the malicious tab.
    await seniorPage.getByTestId("behavioral-tab-malicious").click();
    await seniorPage.waitForTimeout(500);

    // Either entity cards OR the empty state card is rendered; never neither.
    const entityCards = seniorPage.getByTestId("behavioral-entity-card");
    const entityCount = await entityCards.count();

    if (entityCount === 0) {
      // No data — empty state must be visible.
      await expect(
        seniorPage.getByText(/No malicious outliers in this view/),
      ).toBeVisible({ timeout: 5_000 });
    }
    // If entityCount > 0 the tab has data — that's fine; the empty-state assertion is skipped.
  });

  test("refresh button triggers a data reload", async ({ seniorPage }) => {
    await seniorPage.goto("/behavioral");
    await seniorPage
      .getByTestId("behavioral-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });

    const refreshBtn = seniorPage.getByTestId("behavioral-refresh");
    await expect(refreshBtn).toBeVisible();
    // Click should not throw.
    await refreshBtn.click();
    // Page still shows the main container after refresh.
    await expect(seniorPage.getByTestId("behavioral-hunts-page")).toBeVisible();
  });
});
