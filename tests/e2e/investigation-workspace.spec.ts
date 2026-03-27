/**
 * E2E tests -- Investigation Workspace (chat + event panels).
 *
 * Stubs: frontend build not yet wired.  Every test is test.skip().
 */

import { test, expect } from '@playwright/test';

/**
 * Helper: log in as admin, create an investigation, and navigate to its
 * workspace.  Returns the investigation id.
 */
async function setupWorkspace(page: import('@playwright/test').Page): Promise<string> {
  // Log in
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: /log\s*in/i }).click();
  await page.waitForURL('**/');

  // Click the first investigation card to open its workspace
  const firstCard = page.locator('[data-testid="investigation-card"]').first();
  await firstCard.click();

  // Wait for workspace URL pattern /investigations/:id
  await page.waitForURL('**/investigations/**');

  // Extract investigation id from URL
  const url = page.url();
  const match = url.match(/investigations\/(inv_[a-zA-Z0-9]+)/);
  return match ? match[1] : 'unknown';
}

test.describe('Investigation Workspace', () => {
  test.skip('workspace loads for investigation', async ({ page }) => {
    const investigationId = await setupWorkspace(page);
    expect(investigationId).not.toBe('unknown');

    // The workspace should display the chat panel and event timeline
    await expect(page.locator('[data-testid="chat-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="event-panel"]')).toBeVisible();

    // Investigation title should be visible somewhere in the header
    await expect(page.getByRole('heading')).toBeVisible();
  });

  test.skip('send message in agent chat', async ({ page }) => {
    await setupWorkspace(page);

    // Locate the chat input
    const chatInput = page.getByPlaceholder(/message|chat|type/i);
    await expect(chatInput).toBeVisible();

    // Type and send a message
    await chatInput.fill('Analyze the suspicious login from 10.0.0.50');
    await page.getByRole('button', { name: /send/i }).click();

    // The message should appear in the chat history
    await expect(
      page.getByText('Analyze the suspicious login from 10.0.0.50')
    ).toBeVisible();
  });
});
