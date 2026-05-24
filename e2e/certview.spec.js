const { test, expect } = require('@playwright/test');

const baseURL = process.env.CERTVIEW_E2E_BASE_URL || 'http://127.0.0.1:18080';
const siteHost = process.env.CERTVIEW_E2E_HOST || 'www.gosuslugi.ru';
const unresolvedHost = process.env.CERTVIEW_E2E_UNRESOLVED_HOST || 'не-существует.invalid';

async function waitIdle(page) {
  await page.waitForFunction(() => !document.querySelector('#loading').classList.contains('active'));
}

async function expectReady(page) {
  await waitIdle(page);
  await expect(page.locator('#error-box')).not.toHaveClass(/active/);
  await expect(page.locator('#results')).toHaveClass(/active/);
  await expect(page.locator('#chain-tree .chain-node').first()).toBeVisible();
}

test.describe('certview site links', () => {
  test.beforeEach(async ({ page }) => {
    page.on('dialog', dialog => {
      throw new Error(`Unexpected dialog: ${dialog.type()} ${dialog.message()}`);
    });
  });

  test('analyzes site without hash and copied links round-trip', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: baseURL });

    await page.goto(baseURL + '/');
    await page.fill('#pem-input', siteHost);
    await page.click('#pem-btn');
    await expectReady(page);

    const analyzedURL = new URL(page.url());
    expect(analyzedURL.hash).toBe('');
    expect(analyzedURL.pathname).not.toBe('/');

    const linkButtons = page.locator('#chain-tree > .chain-node > .cert-actions button', { hasText: 'Link' });
    const count = await linkButtons.count();
    expect(count).toBeGreaterThan(0);

    const copied = [];
    for (let i = 0; i < count; i++) {
      await linkButtons.nth(i).click();
      const href = await page.evaluate(() => navigator.clipboard.readText());
      copied.push(href);
    }

    expect(new URL(copied[0]).pathname).toBe(analyzedURL.pathname);
    for (const href of copied.slice(1)) {
      expect(new URL(href).pathname).toBe('/');
    }

    for (const href of copied) {
      await page.goto(href);
      await expectReady(page);
    }
  });

  test('shows in-page error without dialog for unresolved host', async ({ page }) => {
    await page.goto(baseURL + '/');
    await page.fill('#pem-input', unresolvedHost);
    await page.click('#pem-btn');
    await waitIdle(page);

    await expect(page.locator('#error-box')).toHaveClass(/active/);
    await expect(page.locator('#error-box')).toContainText('Site fetch failed');
    await expect(page.locator('#results')).not.toHaveClass(/active/);
  });
});
