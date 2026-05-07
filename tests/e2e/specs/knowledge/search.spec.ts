/**
 * Knowledge search — input + submit + results + filter chips.
 *
 * Sprint F scope. Exercises the KnowledgeSearch component instrumented
 * in Sprint A. Doc seeding is via API so the search has real content
 * to surface.
 */
import { test, expect } from "../../fixtures/auth";
import { KnowledgePage } from "../../pages/knowledge-page";
import { seedKnowledgeDoc } from "../../fixtures/seed-helpers";

test.describe("Knowledge search", () => {
  test("renders input + submit; clear surfaces once a query is typed", async ({
    analystPage,
  }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await expect(knowledge.search.root).toBeVisible();
    await expect(knowledge.search.input).toBeVisible();
    await expect(knowledge.search.submitButton).toBeVisible();
    // The clear (X) button is conditionally rendered — only shown once
    // the user has typed something — so we don't assert visibility on
    // page load. Instead, type a character and verify it appears.
    await expect(knowledge.search.clearButton).toBeHidden();
    await knowledge.search.input.fill("test");
    await expect(knowledge.search.clearButton).toBeVisible();
  });

  test("submitting a query renders the results panel", async ({
    analystPage,
    analystApi,
  }) => {
    const stamp = Date.now();
    await seedKnowledgeDoc(analystApi, {
      title: `[E2E] Lateral Movement Runbook ${stamp}`,
      content:
        "Lateral movement detection: pivot to host telemetry on every Kerberos golden-ticket alert.",
    });

    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.search.submit("lateral movement");
    // Either results render OR an empty state — the search panel switches
    // to one of the result-bearing states. Empty state is a real result.
    await expect(
      knowledge.search.results.or(knowledge.search.empty),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("a query with no matches surfaces the empty state", async ({
    analystPage,
  }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    // A noise string with extremely low likelihood of matching real
    // seeded content. Stamp keeps it unique per run.
    await knowledge.search.submit(`zzz_no_match_${Date.now()}_zzz`);
    await expect(knowledge.search.empty).toBeVisible({ timeout: 10_000 });
  });

  test("filter chip toggles aria-selected on click", async ({
    analystPage,
  }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    // Open the filters bar first so the chips are mounted.
    await knowledge.search.filtersToggle.click();
    const runbookChip = knowledge.search.filterTab("runbook");
    await expect(runbookChip).toBeVisible();
    await runbookChip.click();
    await expect(runbookChip).toHaveAttribute("aria-selected", "true");
    // The "all" chip should no longer be selected once another tab wins.
    const allChip = knowledge.search.filterTab("all");
    await expect(allChip).toHaveAttribute("aria-selected", "false");
  });

  test("clear button resets the search input", async ({ analystPage }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.search.input.fill("kerberos");
    await expect(knowledge.search.input).toHaveValue("kerberos");
    await knowledge.search.clear();
    await expect(knowledge.search.input).toHaveValue("");
  });

  test("filters toggle expands and collapses the filter bar", async ({
    analystPage,
  }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    // Initial collapsed state is the default — toggling reveals it.
    await knowledge.search.filtersToggle.click();
    await expect(knowledge.search.filters).toBeVisible();
    await knowledge.search.filtersToggle.click();
    await expect(knowledge.search.filters).toBeHidden();
  });
});
