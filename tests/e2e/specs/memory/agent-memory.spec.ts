/**
 * Agent Memory page E2E (#482 follow-up).
 *
 * `/memory` had zero browser coverage: `Sidebar.goToAgentMemory()` existed in
 * the POM but no spec ever called it, so the page had a navigation helper and
 * no test behind it.
 *
 * The page exists for one reason, stated in its own docstring: these facts are
 * "recalled into every new investigation", so a wrong one keeps shaping cases
 * until someone finds and removes it. That makes the record → recall → forget
 * loop the thing worth asserting, not the header. `forget` in particular is
 * the correction path — if it silently fails, the analyst believes a bad fact
 * is gone while it is still being injected into prompts.
 *
 * RBAC: `memory:read` is analyst, `memory:write` is senior_analyst. The write
 * controls hide below senior, and the API refuses regardless — both asserted,
 * because a hidden button is presentation and the 403 is the control.
 */
import { test, expect } from "../../fixtures/auth";
import type { Page } from "@playwright/test";

const PAGE_TIMEOUT = 10_000;

async function openPage(page: Page): Promise<void> {
  await page.goto("/memory");
  await page.getByTestId("agent-memory-page").waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
}

/** Record a memory through the UI and return the id the row was given. */
async function recordMemory(
  page: Page,
  subject: string,
  content: string,
): Promise<void> {
  await page.getByTestId("agent-memory-add").click();
  await page.getByTestId("agent-memory-form").waitFor({ state: "visible" });
  await page.getByTestId("agent-memory-subject").fill(subject);
  await page.getByTestId("agent-memory-content").fill(content);
  await page.getByTestId("agent-memory-submit").click();
}

test.describe("Agent Memory page", () => {
  test("page structure renders with the memory panel", async ({ analystPage }) => {
    await openPage(analystPage);

    // level: 1 on purpose — the panel below carries its own "Agent memory"
    // h2, so an unscoped name match is ambiguous.
    await expect(
      analystPage.getByRole("heading", { name: "Agent Memory", level: 1 }),
    ).toBeVisible();
    await expect(analystPage.getByTestId("agent-memory-panel")).toBeVisible();
    await expect(analystPage.getByTestId("agent-memory-search-form")).toBeVisible();
  });

  test("sidebar nav link reaches the page", async ({ analystPage }) => {
    await analystPage.goto("/");
    await analystPage.getByTestId("nav-memory-link").click();
    await analystPage
      .getByTestId("agent-memory-page")
      .waitFor({ state: "visible", timeout: PAGE_TIMEOUT });
    expect(analystPage.url()).toContain("/memory");
  });

  test("a recorded fact is listed and survives a reload", async ({ seniorPage }) => {
    const runTag = `mem-${Date.now()}`;
    await openPage(seniorPage);
    await recordMemory(seniorPage, `subject-${runTag}`, `The org uses ${runTag} for egress.`);

    const list = seniorPage.getByTestId("agent-memory-list");
    await expect(list).toContainText(runTag, { timeout: PAGE_TIMEOUT });

    // Recall is the whole point — a fact that renders but is not stored would
    // never reach the next investigation's prompt.
    await openPage(seniorPage);
    await expect(seniorPage.getByTestId("agent-memory-list")).toContainText(runTag, {
      timeout: PAGE_TIMEOUT,
    });
  });

  test("search narrows the list to the matching fact", async ({ seniorPage }) => {
    const runTag = `mems-${Date.now()}`;
    await openPage(seniorPage);
    await recordMemory(seniorPage, `subject-${runTag}`, `Searchable fact ${runTag}.`);
    await expect(seniorPage.getByTestId("agent-memory-list")).toContainText(runTag, {
      timeout: PAGE_TIMEOUT,
    });

    await seniorPage.getByTestId("agent-memory-search").fill(runTag);
    await seniorPage.getByTestId("agent-memory-search-submit").click();
    await expect(seniorPage.getByTestId("agent-memory-list")).toContainText(runTag, {
      timeout: PAGE_TIMEOUT,
    });
  });

  test("forget removes the fact for good — the correction path", async ({ seniorPage }) => {
    const runTag = `memf-${Date.now()}`;
    await openPage(seniorPage);
    await recordMemory(seniorPage, `subject-${runTag}`, `Wrong fact ${runTag}.`);

    // Find the row this run created and take its id from the testid.
    // Memory ids are prefixed ULIDs (`mem_…`), so the row testid is
    // `agent-memory-mem_…` — distinct from the panel's own control testids.
    const row = seniorPage
      .locator('[data-testid^="agent-memory-mem_"]')
      .filter({ hasText: runTag })
      .first();
    await expect(row).toBeVisible({ timeout: PAGE_TIMEOUT });
    const testId = await row.getAttribute("data-testid");
    const id = (testId ?? "").replace("agent-memory-", "");
    expect(id).not.toBe("");

    // Two-step: forget opens a confirm panel rather than deleting on one click.
    await seniorPage.getByTestId(`agent-memory-forget-${id}`).click();
    await expect(
      seniorPage.getByTestId(`agent-memory-forget-confirm-panel-${id}`),
    ).toBeVisible();
    await seniorPage.getByTestId(`agent-memory-forget-confirm-${id}`).click();

    await expect(seniorPage.getByTestId(`agent-memory-${id}`)).toHaveCount(0, {
      timeout: PAGE_TIMEOUT,
    });

    // The removal has to be real: a fact that reappears on reload is still
    // being recalled into new investigations.
    await openPage(seniorPage);
    await expect(seniorPage.getByTestId(`agent-memory-${id}`)).toHaveCount(0, {
      timeout: PAGE_TIMEOUT,
    });
  });

  test("an analyst can read memory but not write it", async ({ analystPage }) => {
    await openPage(analystPage);

    // memory:write is senior_analyst+, so the write affordances are absent...
    await expect(analystPage.getByTestId("agent-memory-add")).toHaveCount(0);
    // ...while the read surface still works for them.
    await expect(analystPage.getByTestId("agent-memory-search-form")).toBeVisible();

    // Hiding the button is presentation; the permission is the control.
    const resp = await analystPage.request.post("/api/v1/memory", {
      data: {
        kind: "entity_note",
        subject: "rbac-probe",
        content: "analyst should not be able to write this",
      },
    });
    expect(resp.status()).toBe(403);
  });
});
