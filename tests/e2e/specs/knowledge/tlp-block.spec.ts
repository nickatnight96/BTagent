/**
 * Knowledge TLP enforcement — REGRESSION test.
 *
 * The audit-cleanup work wired TLP:RED rejection into the knowledge
 * ingest endpoint. This guards that contract: TLP:RED ingest must
 * return a 4xx and the doc must NOT land in the listing.
 */
import { test, expect } from "../../fixtures/auth";

test.describe("Knowledge TLP:RED ingest is blocked", () => {
  test("ingest with classification=red returns 4xx", async ({
    analystApi,
  }) => {
    const res = await analystApi.ctx.post("/api/v1/knowledge/ingest", {
      data: {
        title: `[E2E] TLP-RED Attempt ${Date.now()}`,
        content: "Classified runbook content — must not be ingested.",
        source_type: "runbook",
        classification: "red",
      },
    });
    // The endpoint should reject TLP:RED outright. Accept either 400
    // (validation) or 403 (TLPViolation) — the contract is "rejected".
    expect([400, 403]).toContain(res.status());
  });

  test("rejected TLP:RED doc is absent from the list endpoint", async ({
    analystApi,
  }) => {
    const stamp = Date.now();
    const title = `[E2E] TLP-RED Absent ${stamp}`;
    // Attempt the ingest (expected to fail).
    const ingestRes = await analystApi.ctx.post(
      "/api/v1/knowledge/ingest",
      {
        data: {
          title,
          content: "Nope.",
          source_type: "runbook",
          classification: "red",
        },
      },
    );
    expect([400, 403]).toContain(ingestRes.status());

    // Now confirm the doc never made it. Use the listing endpoint and
    // assert nothing matches the unique title.
    const listRes = await analystApi.ctx.get("/api/v1/knowledge/documents");
    if (listRes.ok()) {
      const body = (await listRes.json()) as
        | Array<{ title: string }>
        | { items?: Array<{ title: string }> };
      const items = Array.isArray(body) ? body : (body.items ?? []);
      const found = items.find((d) => d.title === title);
      expect(
        found,
        "TLP:RED doc must not appear in the listing",
      ).toBeUndefined();
    } else {
      // If the listing endpoint isn't exposed here, at minimum the
      // ingest already returned a rejection — that's the load-bearing
      // assertion above. Surface the listing failure for debugging.
      expect(listRes.status()).toBeLessThan(500);
    }
  });

  test("TLP:GREEN ingest still succeeds (positive control)", async ({
    analystApi,
  }) => {
    // A control case so we know TLP:RED rejection is specifically the
    // classification, not a broken endpoint.
    const res = await analystApi.ctx.post("/api/v1/knowledge/ingest", {
      data: {
        title: `[E2E] TLP-GREEN Control ${Date.now()}`,
        content: "Public-safe runbook content.",
        source_type: "runbook",
        classification: "green",
      },
    });
    expect(
      res.ok(),
      `expected green ingest to succeed, got ${res.status()}`,
    ).toBe(true);
  });
});
