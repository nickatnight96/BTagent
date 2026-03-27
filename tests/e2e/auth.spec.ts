/**
 * E2E tests -- Authentication flows.
 *
 * These are stubs: the frontend build pipeline is not yet configured,
 * so every test is marked with test.skip().  The structure and selectors
 * reflect the planned React login page.
 */

import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test.skip('login page loads', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('heading')).toContainText('BTagent');
    // The login form should be visible
    await expect(page.getByLabel('Username')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: /log\s*in/i })).toBeVisible();
  });

  test.skip('login with valid credentials', async ({ page }) => {
    await page.goto('/login');

    // Fill the login form with seed admin credentials
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('admin');
    await page.getByRole('button', { name: /log\s*in/i }).click();

    // After successful login the user should be redirected to the PunchList
    await page.waitForURL('**/');
    await expect(page.getByText(/PunchList|investigations/i)).toBeVisible();
  });

  test.skip('login with invalid credentials shows error', async ({ page }) => {
    await page.goto('/login');

    // Fill with wrong credentials
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('wrong-password');
    await page.getByRole('button', { name: /log\s*in/i }).click();

    // An error message should appear; the user should stay on /login
    await expect(page.getByText(/invalid|error|failed/i)).toBeVisible();
    expect(page.url()).toContain('/login');
  });
});
