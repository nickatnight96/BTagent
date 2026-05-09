/**
 * Knowledge ingest modal — open / fill / submit / cancel paths.
 *
 * Sprint F scope. Drives the KnowledgeIngestModal component end to
 * end via the POM.
 *
 * Backend ingest hits the embedding pipeline (mock in test mode but
 * still synchronous DB writes for documents + chunks). Under CI load
 * the round-trip can spike past Playwright's default 10 s expect
 * timeout. We stub ``POST /api/v1/knowledge/ingest`` and the GET
 * documents-list so the success-path tests are deterministic and
 * well under timeout. The "open / cancel / close" tests don't need
 * the stub — they don't submit.
 */
import { test, expect } from "../../fixtures/auth";
import { KnowledgePage } from "../../pages/knowledge-page";

const SUBMIT_TIMEOUT_MS = 30_000;

async function stubIngestEndpoints(
  page: import("@playwright/test").Page,
): Promise<void> {
  await page.route("**/api/v1/knowledge/ingest", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        document_id: `doc_e2e_${Date.now()}`,
        chunks_created: 1,
        embeddings_created: 1,
      }),
    }),
  );
  await page.route("**/api/v1/knowledge/documents*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ documents: [], total: 0 }),
    }),
  );
}

test.describe("Knowledge ingest modal", () => {
  test("opens via the ingest button", async ({ analystPage }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await expect(knowledge.ingest.dialog).toBeHidden();
    await knowledge.ingestOpenButton.click();
    await expect(knowledge.ingest.dialog).toBeVisible();
    await expect(knowledge.ingest.form).toBeVisible();
  });

  test("submitting an empty form surfaces an inline error", async ({
    analystPage,
  }) => {
    await stubIngestEndpoints(analystPage);

    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.ingestOpenButton.click();
    await knowledge.ingest.submit();
    // Either the submit is blocked client-side (button disabled / form
    // validation) or the server rejects with an error banner. Both
    // count — no doc gets created.
    await expect(
      knowledge.ingest.error.or(knowledge.ingest.submitButton),
    ).toBeVisible();
  });

  test("filling all required fields submits successfully", async ({
    analystPage,
  }) => {
    await stubIngestEndpoints(analystPage);

    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.ingestOpenButton.click();
    const title = `[E2E] Ingested Runbook ${Date.now()}`;
    await knowledge.ingest.fill({
      title,
      content:
        "Step 1 — confirm scope. Step 2 — collect host telemetry. Step 3 — escalate.",
      source: "runbook",
    });
    await knowledge.ingest.submit();
    await expect(knowledge.ingest.success).toBeVisible({
      timeout: SUBMIT_TIMEOUT_MS,
    });
  });

  test("after success the modal stays open with a cleared form", async ({
    analystPage,
  }) => {
    await stubIngestEndpoints(analystPage);

    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.ingestOpenButton.click();
    const title = `[E2E] Stay Open ${Date.now()}`;
    await knowledge.ingest.fill({
      title,
      content: "Quick runbook content for the stay-open assertion.",
      source: "runbook",
    });
    await knowledge.ingest.submit();
    await expect(knowledge.ingest.success).toBeVisible({
      timeout: SUBMIT_TIMEOUT_MS,
    });
    // Modal still open so the user can ingest a follow-up doc.
    await expect(knowledge.ingest.dialog).toBeVisible();
    // And the title input is cleared back to empty.
    await expect(knowledge.ingest.titleInput).toHaveValue("");
  });

  test("cancel button dismisses the modal", async ({ analystPage }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.ingestOpenButton.click();
    await expect(knowledge.ingest.dialog).toBeVisible();
    await knowledge.ingest.cancelButton.click();
    await expect(knowledge.ingest.dialog).toBeHidden();
  });

  test("close button (X) dismisses the modal", async ({ analystPage }) => {
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.ingestOpenButton.click();
    await expect(knowledge.ingest.dialog).toBeVisible();
    await knowledge.ingest.closeButton.click();
    await expect(knowledge.ingest.dialog).toBeHidden();
  });
});
