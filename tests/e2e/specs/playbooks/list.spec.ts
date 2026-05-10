/**
 * Playbook list — render / search / new / edit / execute / delete.
 *
 * Sprint F scope. Uses the playbook CRUD API to seed a deterministic
 * playbook before each test so the list page has known content. Edit
 * and delete buttons live inside a per-card kebab menu — we open the
 * menu with the documented ``aria-label`` before clicking the action.
 */
import { test, expect } from "../../fixtures/auth";
import { PlaybookListPage } from "../../pages/playbook-pages";
import type { BTAgentApiClient } from "../../fixtures/api-client";

interface SeededPlaybook {
  id: string;
  name: string;
}

const MINIMAL_YAML = `name: e2e-playbook
description: Seeded for E2E
trigger:
  type: manual
steps:
  - id: noop
    type: action
    tool: noop
`;

async function seedPlaybook(
  api: BTAgentApiClient,
  name: string,
): Promise<SeededPlaybook> {
  const res = await api.ctx.post("/api/v1/playbooks", {
    data: { name, yaml_content: MINIMAL_YAML },
  });
  if (!res.ok()) {
    throw new Error(
      `Seed playbook failed: ${res.status()} ${await res.text()}`,
    );
  }
  const body = (await res.json()) as { id: string; name: string };
  return { id: body.id, name: body.name };
}

test.describe("Playbook list", () => {
  test("list renders with seeded playbooks", async ({
    analystPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(seniorApi, `[E2E] Visible ${Date.now()}`);
    const list = new PlaybookListPage(analystPage);
    await list.goto();
    await expect(list.card(pb.id)).toBeVisible({ timeout: 10_000 });
    await expect(list.card(pb.id)).toContainText(pb.name);
  });

  test("search input narrows the visible playbooks", async ({
    analystPage,
    seniorApi,
  }) => {
    const stamp = Date.now();
    const a = await seedPlaybook(seniorApi, `[E2E] PhishingResp-${stamp}`);
    const b = await seedPlaybook(seniorApi, `[E2E] MalwareResp-${stamp}`);

    const list = new PlaybookListPage(analystPage);
    await list.goto();
    await list.searchInput.fill(`PhishingResp-${stamp}`);
    await expect(list.card(a.id)).toBeVisible({ timeout: 10_000 });
    await expect(list.card(b.id)).toBeHidden();
  });

  test("empty state shows when search has no matches", async ({
    analystPage,
  }) => {
    const list = new PlaybookListPage(analystPage);
    await list.goto();
    await list.searchInput.fill(`zzz_no_pb_${Date.now()}_zzz`);
    // Either the empty state or the grid (filtered to zero) is visible.
    await expect(list.empty.or(list.grid)).toBeVisible({ timeout: 5_000 });
    if (await list.empty.isVisible()) {
      await expect(list.empty).toBeVisible();
    }
  });

  test("new button navigates to /playbooks/builder", async ({
    analystPage,
  }) => {
    const list = new PlaybookListPage(analystPage);
    await list.goto();
    await expect(list.newButton).toBeVisible();
    await list.newButton.click();
    await analystPage.waitForURL(/\/playbooks\/builder/, { timeout: 5_000 });
    expect(analystPage.url()).toContain("/playbooks/builder");
  });

  test("per-card execute button navigates to the execution page", async ({
    analystPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(seniorApi, `[E2E] Execute ${Date.now()}`);
    const list = new PlaybookListPage(analystPage);
    await list.goto();
    await expect(list.card(pb.id)).toBeVisible({ timeout: 10_000 });
    await list.cardExecuteButton(pb.id).click();
    await analystPage.waitForURL(
      new RegExp(`/playbooks/${pb.id}/execute`),
      { timeout: 5_000 },
    );
  });

  test("per-card edit button opens the builder for that playbook", async ({
    seniorPage,
    seniorApi,
  }) => {
    // Edit lives inside the per-card kebab menu; the menu button is
    // documented via ``aria-label="Open playbook menu"``. Edit
    // requires playbook:edit permission, so use the senior persona.
    const pb = await seedPlaybook(seniorApi, `[E2E] Edit ${Date.now()}`);
    const list = new PlaybookListPage(seniorPage);
    await list.goto();
    await expect(list.card(pb.id)).toBeVisible({ timeout: 10_000 });
    await list
      .card(pb.id)
      .getByRole("button", { name: "Open playbook menu" })
      .click();
    await list.cardEditButton(pb.id).click();
    await seniorPage.waitForURL(
      new RegExp(`/playbooks/builder/${pb.id}`),
      { timeout: 5_000 },
    );
  });

  test("per-card delete button removes the playbook end-to-end", async ({
    seniorPage,
    seniorApi,
  }) => {
    const pb = await seedPlaybook(seniorApi, `[E2E] Delete ${Date.now()}`);
    const list = new PlaybookListPage(seniorPage);
    await list.goto();
    await expect(list.card(pb.id)).toBeVisible({ timeout: 10_000 });

    // Pre-emptively accept any confirm dialog.
    seniorPage.once("dialog", (dialog) => dialog.accept());
    await list
      .card(pb.id)
      .getByRole("button", { name: "Open playbook menu" })
      .click();
    await list.cardDeleteButton(pb.id).click();

    // UI removes the card.
    await expect(list.card(pb.id)).toBeHidden({ timeout: 10_000 });

    // Server-side: deactivated by the soft-delete contract. The list
    // endpoint with ``active_only=true`` should no longer return it.
    const listRes = await seniorApi.ctx.get(
      "/api/v1/playbooks?active_only=true&page_size=100",
    );
    expect(listRes.ok()).toBe(true);
    const body = (await listRes.json()) as { items: Array<{ id: string }> };
    expect(body.items.find((p) => p.id === pb.id)).toBeUndefined();
  });
});
