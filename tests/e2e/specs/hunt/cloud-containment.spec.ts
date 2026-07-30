/**
 * Cloud containment proposal E2E (#117 Phase C / #511 / #518).
 *
 * Drives the full promote → proposal → HITL decision path in a real browser:
 * an sts_chaining cloud finding is seeded, promoted from /cloud-hunts, and the
 * CloudContainmentModal that promotion surfaces is exercised against the live
 * ``/cloud/investigations/{id}/containment-proposal`` routes.
 *
 * What this pins that the unit suites cannot:
 *  - the proposal actions really are built from the promoted finding's
 *    evidence (one revoke-role per chain hop, high-value target excluded);
 *  - the senior_analyst who promotes can SEE the proposal but gets no decide
 *    affordances — the containment:execute (incident_commander+) gate's UI
 *    half, with the modal shown BEFORE the redirect so the decision isn't
 *    lost;
 *  - an admin accept flows through the real #106 execute path end-to-end
 *    (mock-first dispatch): selected actions come back ``executed`` with an
 *    audit id, unselected ones stay proposed (partial accept).
 *
 * Seeding mirrors ``cloud-hunts.spec.ts``: per-run unique IDs/ARNs so shards
 * never collide, through the real ``POST /api/v1/hunt/findings`` ingest route
 * (hunt:create is analyst+).
 */

import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Seed helper
// ---------------------------------------------------------------------------

interface StsChainSeed {
  findingId: string;
  hops: [string, string];
  highValueTarget: string;
}

/**
 * Seed a cloud sts_chaining finding whose promotion attaches a containment
 * proposal: revoke-role for each traversed hop, never the high-value target
 * itself (revoking the destination role is the outage, not the containment).
 *
 */
async function seedStsChainFinding(page: Page, runTag: string): Promise<StsChainSeed> {
  const accountId = `9876${String(Date.now()).slice(-8)}`;
  const hopA = `arn:aws:iam::${accountId}:role/PivotA-${runTag}`;
  const hopB = `arn:aws:iam::${accountId}:role/PivotB-${runTag}`;
  const highValueTarget = `arn:aws:iam::${accountId}:role/BillingAdmin-${runTag}`;

  const resp = await page.request.post("/api/v1/hunt/findings", {
    data: {
      source: "cloud",
      domain: "cloud",
      title: `STS chain to billing admin ${runTag}`,
      severity: "critical",
      confidence: 0.9,
      technique_ids: ["T1078.004"],
      entities: [],
      observables: [],
      description: "Seeded by cloud-containment.spec.ts",
      evidence: {
        provider: "aws",
        account_id: accountId,
        actor_arn: hopA,
        target_arn: highValueTarget,
        detection: "sts_chaining",
        path: [hopA, hopB, highValueTarget],
        high_value_target: highValueTarget,
        hop_count: 3,
      },
    },
  });
  expect(
    resp.ok(),
    `seedStsChainFinding failed: ${resp.status()} ${await resp.text()}`,
  ).toBeTruthy();
  const findingId = ((await resp.json()) as { id: string }).id;
  return { findingId, hops: [hopA, hopB], highValueTarget };
}

/** Promote the seeded finding from the timeline and wait for the containment modal. */
async function promoteToContainmentModal(page: Page, findingId: string) {
  await page.goto("/cloud-hunts");
  await page.getByTestId("cloud-hunts-page").waitFor({ state: "visible", timeout: 10_000 });
  await page.getByTestId("cloud-timeline").waitFor({ state: "visible", timeout: 15_000 });

  const row = page.locator(
    `[data-testid="cloud-timeline-row"][data-finding-id="${findingId}"]`,
  );
  await row.waitFor({ state: "visible", timeout: 15_000 });
  await row.getByTestId("cloud-timeline-expand").click();
  await row.getByTestId("cloud-promote-btn").click();

  await page.getByTestId("cloud-promote-modal").waitFor({ state: "visible", timeout: 5_000 });
  await page.getByTestId("cloud-promote-confirm-btn").click();

  // Promotion attaches the proposal server-side; the page fetches it and
  // shows the modal INSTEAD of navigating straight to the investigation.
  await page
    .getByTestId("cloud-containment-modal")
    .waitFor({ state: "visible", timeout: 15_000 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Cloud containment proposal modal", () => {
  test("senior sees the proposal read-only and can defer the decision", async ({
    seniorPage,
  }) => {
    const seed = await seedStsChainFinding(seniorPage, `cc-senior-${Date.now()}`);
    const { findingId, hops, highValueTarget } = seed;

    await promoteToContainmentModal(seniorPage, findingId);

    // One revoke-role action per traversed hop; the high-value destination is
    // deliberately NOT a proposed target (that would be the outage).
    const actions = seniorPage.getByTestId("cloud-containment-action");
    await expect(actions).toHaveCount(2);
    await expect(actions.filter({ hasText: hops[0] })).toHaveCount(1);
    await expect(actions.filter({ hasText: hops[1] })).toHaveCount(1);
    await expect(actions.filter({ hasText: highValueTarget })).toHaveCount(0);

    // senior_analyst promoted it but cannot decide: the containment:execute
    // notice shows, and there are no accept/reject/select affordances.
    await expect(seniorPage.getByTestId("cloud-containment-modal")).toContainText(
      "incident commander",
    );
    await expect(seniorPage.getByTestId("cloud-containment-accept")).toHaveCount(0);
    await expect(seniorPage.getByTestId("cloud-containment-reject")).toHaveCount(0);
    await expect(
      seniorPage.locator('[data-testid^="cloud-containment-select-"]'),
    ).toHaveCount(0);

    // Deferring must still land on the promoted investigation — the proposal
    // stays `proposed` on it for an IC to decide later.
    await seniorPage.getByTestId("cloud-containment-dismiss").click();
    await seniorPage.waitForURL(/\/investigations\/inv_/, { timeout: 10_000 });
  });

  test("admin partial-accept executes the selected action with an audit id", async ({
    adminPage,
  }) => {
    const seed = await seedStsChainFinding(adminPage, `cc-admin-${Date.now()}`);
    const { findingId, hops } = seed;

    await promoteToContainmentModal(adminPage, findingId);

    // Admin holds containment:execute → per-action checkboxes are present and
    // start all-selected.
    const checkboxes = adminPage.locator('[data-testid^="cloud-containment-select-"]');
    await expect(checkboxes).toHaveCount(2);

    // Partial accept: leave the second hop out of the decision.
    const hopBRow = adminPage
      .getByTestId("cloud-containment-action")
      .filter({ hasText: hops[1] });
    await hopBRow.locator('input[type="checkbox"]').uncheck();

    await adminPage
      .getByTestId("cloud-containment-rationale")
      .fill("E2E: break the first pivot hop only");
    await adminPage.getByTestId("cloud-containment-accept").click();

    // The accept runs the REAL #106 execute path (mock-first dispatch): the
    // selected action comes back executed with its hash-chained audit row id.
    await expect(adminPage.getByTestId("cloud-containment-decided")).toBeVisible({
      timeout: 15_000,
    });
    const statuses = adminPage.locator('[data-testid^="cloud-containment-status-"]');
    await expect(statuses).toHaveCount(1);
    await expect(statuses.first()).toContainText("executed");
    await expect(statuses.first()).toContainText("audit");
    // The refusal channel must be silent on a clean execute.
    await expect(adminPage.getByTestId("cloud-containment-refusal")).toHaveCount(0);
    await expect(adminPage.getByTestId("cloud-containment-error")).toHaveCount(0);

    // The unselected hop kept no decision — visible as a status-free row.
    await expect(
      hopBRow.locator('[data-testid^="cloud-containment-status-"]'),
    ).toHaveCount(0);

    await adminPage.getByTestId("cloud-containment-dismiss").click();
    await adminPage.waitForURL(/\/investigations\/inv_/, { timeout: 10_000 });
  });

  test("promoting a non-IAM cloud finding navigates straight through — no modal", async ({
    seniorPage,
  }) => {
    // Guards handlePromoteConfirm's 404 branch: a finding class that attaches
    // no proposal must never block the promote behind a missing modal.
    const runTag = `cc-plain-${Date.now()}`;
    const resp = await seniorPage.request.post("/api/v1/hunt/findings", {
      data: {
        source: "cloud",
        domain: "cloud",
        title: `Plain cloud event ${runTag}`,
        severity: "medium",
        confidence: 0.8,
        technique_ids: [],
        entities: [],
        observables: [],
        description: "Seeded by cloud-containment.spec.ts",
        evidence: {
          provider: "aws",
          account_id: `1234${String(Date.now()).slice(-8)}`,
          actor_arn: `arn:aws:iam::123456789012:role/Reader-${runTag}`,
        },
      },
    });
    expect(resp.ok(), `seed failed: ${resp.status()} ${await resp.text()}`).toBeTruthy();
    const findingId = ((await resp.json()) as { id: string }).id;

    await seniorPage.goto("/cloud-hunts");
    await seniorPage
      .getByTestId("cloud-hunts-page")
      .waitFor({ state: "visible", timeout: 10_000 });
    await seniorPage.getByTestId("cloud-timeline").waitFor({ state: "visible", timeout: 15_000 });

    const row = seniorPage.locator(
      `[data-testid="cloud-timeline-row"][data-finding-id="${findingId}"]`,
    );
    await row.waitFor({ state: "visible", timeout: 15_000 });
    await row.getByTestId("cloud-timeline-expand").click();
    await row.getByTestId("cloud-promote-btn").click();
    await seniorPage
      .getByTestId("cloud-promote-modal")
      .waitFor({ state: "visible", timeout: 5_000 });
    await seniorPage.getByTestId("cloud-promote-confirm-btn").click();

    await seniorPage.waitForURL(/\/investigations\/inv_/, { timeout: 15_000 });
    await expect(seniorPage.getByTestId("cloud-containment-modal")).toHaveCount(0);
  });
});
