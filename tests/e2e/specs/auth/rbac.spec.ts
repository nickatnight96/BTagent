/**
 * RBAC + cross-org IDOR — make sure the audit-cleanup work actually
 * blocks at the API layer, end-to-end. These tests would have caught
 * the original IDOR bug ("any authenticated user can read any
 * investigation by ID").
 */
import { test, expect } from "../../fixtures/auth";
import { seedInvestigationWithIOCs } from "../../fixtures/seed-helpers";

test("analyst CAN read their own investigation", async ({ analystApi }) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi);
  const fetched = await analystApi.getInvestigation(investigation.id);
  expect(fetched.id).toBe(investigation.id);
});

test("analyst CANNOT read another analyst's investigation in the same org", async ({
  analystApi,
  seniorApi,
}) => {
  // Senior creates an investigation NOT assigned to analyst1.
  const senior = await seniorApi.createInvestigation({
    title: "[E2E] Senior-owned case",
    severity: "medium",
    tlp_level: "green",
  });

  // Plain analyst tries to read by id — must 404 (ownership check).
  const res = await analystApi.ctx.get(`/api/v1/investigations/${senior.id}`);
  expect([403, 404]).toContain(res.status());
});

test("senior_analyst CAN read another analyst's investigation in the same org", async ({
  analystApi,
  seniorApi,
}) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi);
  // Senior should be able to read it (broad-read in same org).
  const res = await seniorApi.ctx.get(
    `/api/v1/investigations/${investigation.id}`,
  );
  expect(res.status()).toBe(200);
});

test("admin CAN read any investigation across the workspace", async ({
  analystApi,
  adminApi,
}) => {
  const { investigation } = await seedInvestigationWithIOCs(analystApi);
  const res = await adminApi.ctx.get(
    `/api/v1/investigations/${investigation.id}`,
  );
  expect(res.status()).toBe(200);
});

test("non-owner cannot mutate another user's IOC", async ({
  analystApi,
  seniorApi,
}) => {
  const { investigation, iocs } = await seedInvestigationWithIOCs(seniorApi);
  const target = iocs[0];
  if (!target) throw new Error("seed should produce at least one IOC");

  const res = await analystApi.ctx.delete(`/api/v1/iocs/${target.id}`);
  expect([403, 404]).toContain(res.status());

  // And the IOC is still there from senior's perspective.
  const remaining = await seniorApi.listIOCs(investigation.id);
  expect(remaining.find((i) => i.id === target.id)).toBeDefined();
});
