/**
 * SQL-injection tautology / DROP TABLE smoke tests.
 *
 * The intent is *not* to find SQL injection — the backend is built on
 * SQLAlchemy + parameterised queries — but to assert defence-in-depth:
 *
 *   * Search/filter inputs accept dangerous strings without 5xx.
 *   * Underlying tables are still readable after the attempt
 *     (i.e. no "actual DROP" semantics leaked through).
 */
import { test, expect } from "../../fixtures/auth";
import {
  seedInvestigationWithIOCs,
  seedKnowledgeDoc,
} from "../../fixtures/seed-helpers";
import { InvestigationListPage } from "../../pages/investigation-list-page";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { KnowledgePage } from "../../pages/knowledge-page";

const TAUTOLOGY = `' OR '1'='1`;
const DROP_TABLE = `'; DROP TABLE users;--`;

test.describe("SQL-i — search inputs do not 5xx", () => {
  test("IOC search accepts tautology — graceful response", async ({
    analystPage,
    analystApi,
  }) => {
    await seedInvestigationWithIOCs(analystApi);

    const ioc = new IOCNotebookPage(analystPage);
    await ioc.goto();
    await ioc.searchInput.fill(TAUTOLOGY);
    // The error banner must not appear (UI handled the response).
    await analystPage.waitForTimeout(500);
    const errVisible = await ioc.error.isVisible().catch(() => false);
    expect(errVisible).toBe(false);
  });

  test("Investigation search accepts DROP-TABLE — graceful response", async ({
    analystPage,
    analystApi,
  }) => {
    await seedInvestigationWithIOCs(analystApi);

    const list = new InvestigationListPage(analystPage);
    await list.goto();
    await list.search(DROP_TABLE);
    await analystPage.waitForTimeout(500);
    const errVisible = await list.error.isVisible().catch(() => false);
    expect(errVisible).toBe(false);
  });

  test("MITRE search accepts tautology — graceful response", async ({
    analystPage,
  }) => {
    await analystPage.goto("/mitre");
    // The MITRE matrix has its own search input. We hit the API layer
    // directly by loading the page after mounting the search query
    // string — guarantees the backend sees the payload.
    const url = `/mitre?q=${encodeURIComponent(TAUTOLOGY)}`;
    const resp = await analystPage.goto(url);
    expect(resp).not.toBeNull();
    if (resp) {
      // Server must not 5xx. 200 (rendered) or 4xx (validated) acceptable.
      expect(resp.status()).toBeLessThan(500);
    }
  });

  test("Knowledge search accepts DROP-TABLE — graceful response", async ({
    analystPage,
    seniorApi,
  }) => {
    // ``knowledge:ingest`` requires SENIOR_ANALYST (rbac.py:54).
    await seedKnowledgeDoc(seniorApi);
    const knowledge = new KnowledgePage(analystPage);
    await knowledge.goto();
    await knowledge.search.submit(DROP_TABLE);
    await analystPage.waitForTimeout(500);
    // The search-error banner must not show.
    const errVisible = await knowledge.search.error
      .isVisible()
      .catch(() => false);
    expect(errVisible).toBe(false);
  });

  test("post-injection: seeded data is still readable", async ({
    analystApi,
    seniorApi,
  }) => {
    // Seed before anyone has a chance to "drop" anything. Knowledge
    // ingest requires senior; investigations / IOCs are analyst-OK.
    const seeded = await seedInvestigationWithIOCs(analystApi);
    await seedKnowledgeDoc(seniorApi);

    // Trigger the dangerous strings via direct API search params.
    await analystApi.ctx
      .get(
        `/api/v1/investigations?q=${encodeURIComponent(DROP_TABLE)}`,
      )
      .catch(() => undefined);
    await analystApi.ctx
      .get(`/api/v1/iocs?q=${encodeURIComponent(TAUTOLOGY)}`)
      .catch(() => undefined);
    await analystApi.ctx
      .get(
        `/api/v1/knowledge/search?q=${encodeURIComponent(DROP_TABLE)}`,
      )
      .catch(() => undefined);

    // Re-read: the seeded investigation MUST still be there.
    const refetched = await analystApi.getInvestigation(seeded.investigation.id);
    expect(refetched.id).toBe(seeded.investigation.id);

    // The IOC list must still come back.
    const iocs = await analystApi.listIOCs(seeded.investigation.id);
    expect(iocs.length).toBeGreaterThan(0);
  });
});
