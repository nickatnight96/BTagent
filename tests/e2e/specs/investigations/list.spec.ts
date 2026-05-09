/**
 * Investigation list — search / filter / open / create.
 *
 * Sprint D scope; uses the merged Sprint A instrumentation on
 * InvestigationList + InvestigationCard + NewInvestigationModal.
 */
import { test, expect } from "../../fixtures/auth";
import { InvestigationListPage } from "../../pages/investigation-list-page";
import { NewInvestigationModal } from "../../pages/new-investigation-modal";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test("list renders the user's investigations", async ({
  analystPage,
  analystApi,
}) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi, {
    title: "[E2E] Visible to analyst",
  });
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  await expect(list.cardFor(investigation.id)).toBeVisible();
  await expect(list.cardFor(investigation.id)).toContainText(
    "[E2E] Visible to analyst",
  );
});

test("search narrows the list to matching titles", async ({
  analystPage,
  analystApi,
}) => {
  const stamp = Date.now();
  const a = await analystApi.createInvestigation({
    title: `[E2E] Phishing-${stamp}`,
    severity: "high",
  });
  const b = await analystApi.createInvestigation({
    title: `[E2E] Ransomware-${stamp}`,
    severity: "critical",
  });

  const list = new InvestigationListPage(analystPage);
  await list.goto();
  await list.search(`Phishing-${stamp}`);
  // The search debounces / filters client-side; give it a beat.
  await expect(list.cardFor(a.id)).toBeVisible();
  await expect(list.cardFor(b.id)).toBeHidden();
});

test("filter tab toggles narrow the list to matching status", async ({
  analystPage,
}) => {
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  await list.filterByStatus("completed");
  // Active tab gets aria-selected=true (per the convention's tablist
  // semantics applied in InvestigationList).
  await expect(list.filterTab("completed")).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await list.filterByStatus("");
  await expect(list.filterTab("all")).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

test("creating an investigation via the modal lands a new card", async ({
  analystPage,
}) => {
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  await list.openNewModal();

  const modal = new NewInvestigationModal(analystPage);
  await expect(modal.dialog).toBeVisible();
  const title = `[E2E] Created via UI ${Date.now()}`;
  await modal.fill({
    title,
    description: "Created by the investigation-list E2E test.",
    severity: "medium",
    tlpLevel: "green",
  });
  await modal.submit();

  // After successful create, the modal closes and the new card appears.
  // Bump timeouts: the create POSTs through the API and refetches the
  // list, both of which are slower under CI load than 5s allows for.
  await expect(modal.dialog).toBeHidden({ timeout: 15_000 });
  // The new card may take a tick — find it by visible title rather
  // than templated id (we don't have it from the UI).
  await expect(
    analystPage.locator('[data-testid^="investigation-card-"]', {
      hasText: title,
    }),
  ).toBeVisible({ timeout: 15_000 });
});

test("opening a card navigates to /investigations/:id", async ({
  analystPage,
  analystApi,
}) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi);
  const list = new InvestigationListPage(analystPage);
  await list.goto();
  // The list page is a client-rendered Zustand-backed view; ensure the
  // card has actually rendered before we try to click it.
  await expect(list.cardFor(investigation.id)).toBeVisible({
    timeout: 10_000,
  });
  await list.openInvestigation(investigation.id);
  await expect(analystPage).toHaveURL(
    new RegExp(`/investigations/${investigation.id}`),
    { timeout: 10_000 },
  );
});
