/**
 * Persona-fixture smoke — proves each ``storageState`` from
 * ``auth.setup.ts`` actually grants authenticated access to the SPA.
 * If this fails, every persona-dependent test downstream is broken.
 */
import { test, expect } from "../../fixtures/auth";

test("admin persona lands on dashboard with admin role badge", async ({
  adminPage,
}) => {
  await adminPage.goto("/");
  await expect(adminPage.getByTestId("header-user-name")).toHaveText("admin");
  await expect(adminPage.getByTestId("header-user-role")).toContainText(
    /admin/i,
  );
});

test("analyst persona lands on dashboard with analyst role badge", async ({
  analystPage,
}) => {
  await analystPage.goto("/");
  await expect(analystPage.getByTestId("header-user-name")).toHaveText(
    "analyst1",
  );
  await expect(analystPage.getByTestId("header-user-role")).toContainText(
    /analyst/i,
  );
});

test("senior persona lands on dashboard with senior_analyst role badge", async ({
  seniorPage,
}) => {
  await seniorPage.goto("/");
  await expect(seniorPage.getByTestId("header-user-name")).toHaveText("senior1");
  await expect(seniorPage.getByTestId("header-user-role")).toContainText(
    /senior/i,
  );
});

test("anonymous fixture is unauthenticated", async ({ anonymousPage }) => {
  await anonymousPage.goto("/");
  await anonymousPage.waitForURL(/\/login(\?|\#|$)/);
  expect(anonymousPage.url()).toContain("/login");
});
