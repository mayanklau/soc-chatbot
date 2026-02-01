import { test, expect } from '@playwright/test';

test('SOC Chatbot: page loads', async ({ page }) => {
  await page.goto('/');
  // Basic sanity: page should render something
  await expect(page.locator('body')).toBeVisible();
});
