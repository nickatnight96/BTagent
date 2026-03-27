/**
 * E2E tests -- PunchList (investigation dashboard).
 *
 * Stubs: frontend build not yet wired.  Every test is test.skip().
 */

import { test, expect } from '@playwright/test';

/**
 * Helper: log in as admin via the UI and return to the caller.
 * Reusable across PunchList tests that need an authenticated session.
 */
async function loginAsAdmin(page: import('@playwright/test').Page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: /log\s*in/i }).click();
  await page.waitForURL('**/');
}

test.describe('PunchList', () => {
  test.skip('PunchList page loads', async ({ page }) => {
    await loginAsAdmin(page);

    // The main dashboard should display investigation cards
    await expect(page.getByText(/PunchList|investigations/i)).toBeVisible();

    // There should be at least one investigation card (seed data)
    const cards = page.locator('[data-testid="investigation-card"]');
    await expect(cards.first()).toBeVisible();
  });

  test.skip('create investigation from PunchList', async ({ page }) => {
    await loginAsAdmin(page);

    // Click the "New Investigation" button
    await page.getByRole('button', { name: /new|create/i }).click();

    // A creation form / modal should appear
    await page.getByLabel(/title/i).fill('E2E Test Investigation');
    await page.getByLabel(/description/i).fill('Created by Playwright E2E test');

    // Select severity if dropdown exists
    const severitySelect = page.getByLabel(/severity/i);
    if (await severitySelect.isVisible()) {
      await severitySelect.selectOption('high');
    }

    // Submit
    await page.getByRole('button', { name: /create|submit|save/i }).click();

    // Verify the new investigation card appears on the PunchList
    await expect(page.getByText('E2E Test Investigation')).toBeVisible();
  });
});
