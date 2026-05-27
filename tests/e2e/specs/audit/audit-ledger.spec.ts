/**
 * Audit Ledger — tamper-evident hash-chain ledger view.
 *
 * ``audit:view`` is a senior_analyst+ permission, so the ledger data
 * loads for the senior persona and 403s for a plain analyst (the page
 * still renders its shell — the route is auth-gated only, RBAC is
 * enforced server-side, surfacing as an error banner).
 */
import { test, expect } from "../../fixtures/auth";
import { AuditLedgerPage } from "../../pages/slice-pages";

test.describe("Audit Ledger", () => {
  test("ledger loads for the senior persona", async ({ seniorPage }) => {
    const audit = new AuditLedgerPage(seniorPage);
    await audit.goto();
    await expect(audit.root).toBeVisible();
    await expect(audit.header.title).toHaveText("Audit Ledger");
    // The chain-integrity banner and the entries table both render once
    // the load completes.
    await expect(audit.table).toBeVisible({ timeout: 20_000 });
    await expect(audit.root).toContainText("hash chain", { ignoreCase: true });
  });

  test("analyst is denied the audit data (server-side RBAC)", async ({
    analystPage,
  }) => {
    const audit = new AuditLedgerPage(analystPage);
    await audit.goto();
    // Shell renders, but the data fetch is rejected -> error banner.
    await expect(audit.error).toBeVisible({ timeout: 20_000 });
  });
});
