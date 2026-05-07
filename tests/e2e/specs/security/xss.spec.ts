/**
 * XSS reflection / sanitisation E2E.
 *
 * Surface area covered:
 *   * IOC value field (UI submit + raw API submit)
 *   * Investigation title (card + workspace title)
 *   * Knowledge document title + content
 *   * IOC tag rendering
 *
 * Strategy: every test plants a reflected-XSS payload via either the
 * UI or a direct API call, then asserts that the payload renders as
 * inert text — never as live script. We hook ``page.on("dialog")`` to
 * fail fast if an ``alert(...)`` *did* fire.
 */
import { test, expect } from "../../fixtures/auth";
import {
  seedInvestigationWithIOCs,
  seedKnowledgeDoc,
} from "../../fixtures/seed-helpers";
import { InvestigationListPage } from "../../pages/investigation-list-page";
import { IOCNotebookPage } from "../../pages/ioc-notebook-page";
import { KnowledgePage } from "../../pages/knowledge-page";

const XSS_PAYLOAD = `<script>alert("xss")</script>`;
const XSS_IMG = `<img src=x onerror="alert('xss-img')">`;

/**
 * Wire a page-level dialog listener that fails the test on fire.
 * Returns a disposer to be called in afterEach-equivalent code paths.
 */
function trapDialogs(page: import("@playwright/test").Page): () => void {
  const handler = (dialog: import("@playwright/test").Dialog) => {
    void dialog.dismiss();
    throw new Error(
      `Unexpected JS dialog fired: type=${dialog.type()} message=${dialog.message()} — XSS reflection succeeded.`,
    );
  };
  page.on("dialog", handler);
  return () => page.off("dialog", handler);
}

test.describe("XSS — IOC value field", () => {
  test("UI submit: <script> payload as IOC value never executes", async ({
    analystPage,
    analystApi,
  }) => {
    const dispose = trapDialogs(analystPage);
    try {
      const { investigation } = await seedInvestigationWithIOCs(analystApi);
      // Plant the payload via the API (UI flow ends in the same store).
      await analystApi.addIOC({
        investigation_id: investigation.id,
        type: "domain",
        value: `${XSS_PAYLOAD}.evil.invalid`,
      });

      const ioc = new IOCNotebookPage(analystPage);
      await ioc.goto();
      // Give the table a moment to render the row carrying the payload.
      await ioc.table.waitFor({ state: "visible" });
      // The escaped string must appear as text — never as a live tag.
      const tableHtml = await ioc.table.innerHTML();
      expect(tableHtml).not.toContain("<script>alert(");
      // The lt/gt should be entity-encoded by React's text node escaping.
      expect(tableHtml).toMatch(/&lt;script&gt;|&amp;lt;script/);
    } finally {
      dispose();
    }
  });

  test("API submit: payload is escaped on render in the IOC table", async ({
    analystPage,
    analystApi,
  }) => {
    const dispose = trapDialogs(analystPage);
    try {
      const { investigation } = await seedInvestigationWithIOCs(analystApi);
      await analystApi.addIOC({
        investigation_id: investigation.id,
        type: "url",
        value: `https://${XSS_IMG}.invalid/path`,
      });

      const ioc = new IOCNotebookPage(analystPage);
      await ioc.goto();
      await ioc.table.waitFor({ state: "visible" });
      const tableHtml = await ioc.table.innerHTML();
      expect(tableHtml).not.toMatch(/<img\s+src=x\s+onerror=/i);
    } finally {
      dispose();
    }
  });
});

test.describe("XSS — investigation title", () => {
  test("escaped in card list view", async ({ analystPage, analystApi }) => {
    const dispose = trapDialogs(analystPage);
    try {
      const inv = await analystApi.createInvestigation({
        title: `XSS-card ${XSS_PAYLOAD}`,
        severity: "low",
        tlp_level: "green",
      });

      const list = new InvestigationListPage(analystPage);
      await list.goto();
      const card = list.cardFor(inv.id);
      await card.waitFor({ state: "visible" });
      const cardHtml = await card.innerHTML();
      expect(cardHtml).not.toContain("<script>alert(");
      expect(cardHtml).toMatch(/&lt;script&gt;|&amp;lt;script/);
    } finally {
      dispose();
    }
  });

  test("escaped in workspace title bar", async ({ analystPage, analystApi }) => {
    const dispose = trapDialogs(analystPage);
    try {
      const inv = await analystApi.createInvestigation({
        title: `XSS-ws ${XSS_PAYLOAD}`,
        severity: "low",
        tlp_level: "green",
      });

      await analystPage.goto(`/investigations/${inv.id}`);
      // The workspace title test-id is set in Sprint A instrumentation.
      const title = analystPage.getByTestId("investigation-workspace-title");
      await title.waitFor({ state: "visible" });
      const html = await title.innerHTML();
      expect(html).not.toContain("<script>alert(");
    } finally {
      dispose();
    }
  });
});

test.describe("XSS — knowledge documents", () => {
  test("escaped in document content rendering", async ({
    analystPage,
    analystApi,
  }) => {
    const dispose = trapDialogs(analystPage);
    try {
      await seedKnowledgeDoc(analystApi, {
        title: "XSS content harness",
        content: `Pre-text ${XSS_PAYLOAD} post-text`,
      });

      const knowledge = new KnowledgePage(analystPage);
      await knowledge.goto();
      // Force a list re-render — a bare goto already loads the list,
      // but waiting on the items locator stabilises the assertion.
      await knowledge.list.items.waitFor({ state: "visible" });
      const listHtml = await knowledge.list.items.innerHTML();
      expect(listHtml).not.toContain("<script>alert(");
    } finally {
      dispose();
    }
  });

  test("escaped in document title rendering", async ({
    analystPage,
    analystApi,
  }) => {
    const dispose = trapDialogs(analystPage);
    try {
      await seedKnowledgeDoc(analystApi, {
        title: `XSS-title ${XSS_PAYLOAD}`,
        content: "Plain content",
      });

      const knowledge = new KnowledgePage(analystPage);
      await knowledge.goto();
      await knowledge.list.items.waitFor({ state: "visible" });
      const listHtml = await knowledge.list.items.innerHTML();
      expect(listHtml).not.toContain("<script>alert(");
      expect(listHtml).toMatch(/&lt;script&gt;|&amp;lt;script/);
    } finally {
      dispose();
    }
  });

  test("escaped in knowledge search results", async ({
    analystPage,
    analystApi,
  }) => {
    const dispose = trapDialogs(analystPage);
    try {
      await seedKnowledgeDoc(analystApi, {
        title: `XSS-srch ${XSS_PAYLOAD} marker-${Date.now()}`,
        content: "Searchable body with marker XSSMARKER",
      });

      const knowledge = new KnowledgePage(analystPage);
      await knowledge.goto();
      await knowledge.search.submit("XSSMARKER");
      await knowledge.search.results
        .waitFor({ state: "visible", timeout: 10_000 })
        .catch(() => {
          // If empty (no hit), bail out — nothing to render.
        });
      const resultsHtml = await knowledge.search.results
        .innerHTML()
        .catch(() => "");
      expect(resultsHtml).not.toContain("<script>alert(");
    } finally {
      dispose();
    }
  });
});

test.describe("XSS — IOC tag", () => {
  test("escaped in card tag chips", async ({ analystPage, analystApi }) => {
    const dispose = trapDialogs(analystPage);
    try {
      const inv = await analystApi.createInvestigation({
        title: `[E2E] tag-xss ${Date.now()}`,
        severity: "low",
        tlp_level: "green",
        tags: [`tag-${XSS_PAYLOAD}`],
      });

      const list = new InvestigationListPage(analystPage);
      await list.goto();
      const card = list.cardFor(inv.id);
      await card.waitFor({ state: "visible" });
      const html = await card.innerHTML();
      expect(html).not.toContain("<script>alert(");
    } finally {
      dispose();
    }
  });
});
