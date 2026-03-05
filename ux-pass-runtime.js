const { chromium } = require('playwright');

async function runDesktop() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const page = await context.newPage();
  const consoleErrors = [];
  const dialogs = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`));
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.type());
    await dialog.dismiss();
  });

  await page.goto('http://127.0.0.1:18081/', { waitUntil: 'networkidle' });
  const initialTheme = await page.locator('html').getAttribute('data-theme');
  await page.screenshot({ path: '/tmp/ux-desktop-auth.png', fullPage: true });

  await page.fill('#form-login input[name="email"]', 'admin@example.com');
  await page.fill('#form-login input[name="password"]', 'SecretPass123!');
  await page.click('#form-login button[type="submit"]');
  await page.waitForTimeout(1200);
  await page.click('#tab-mail');
  await page.waitForTimeout(600);

  await page.screenshot({ path: '/tmp/ux-desktop-mail.png', fullPage: true });

  await page.locator('#mail-pane-reader').click();
  await page.keyboard.press('/');
  await page.waitForTimeout(200);
  await page.keyboard.type('probe');
  await page.keyboard.press('Enter');
  await page.locator('#mail-pane-reader').click();
  await page.keyboard.press('c');
  await page.waitForTimeout(300);
  const composeVisible = !(await page.locator('#compose-overlay').evaluate((n) => n.classList.contains('hidden')));
  await page.keyboard.press('Escape');
  await page.waitForTimeout(250);

  await page.click('#tab-settings');
  await page.waitForTimeout(600);
  await page.screenshot({ path: '/tmp/ux-desktop-settings-signin.png', fullPage: true });
  await page.click('#settings-nav-devices');
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/ux-desktop-settings-devices.png', fullPage: true });
  await page.click('#settings-nav-sessions');
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/ux-desktop-settings-sessions.png', fullPage: true });
  await page.fill('#settings-search-input', 'passkey');
  await page.waitForTimeout(220);
  if ((await page.locator('#settings-search-results .settings-search-result').count()) > 0) {
    await page.locator('#settings-search-results .settings-search-result').first().click();
    await page.waitForTimeout(240);
  }

  await page.click('#tab-admin');
  await page.waitForTimeout(700);
  await page.screenshot({ path: '/tmp/ux-desktop-admin-system.png', fullPage: true });
  await page.fill('#admin-search-input', 'feature flags');
  await page.waitForTimeout(220);
  if ((await page.locator('#admin-search-results .settings-search-result').count()) > 0) {
    await page.locator('#admin-search-results .settings-search-result').first().click();
    await page.waitForTimeout(240);
  }

  await page.click('#admin-nav-registrations');
  await page.waitForTimeout(400);
  await page.fill('#admin-reg-q', 'test');
  await page.click('#btn-admin-reg-apply');
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/ux-desktop-admin-registrations.png', fullPage: true });

  await page.click('#admin-nav-users');
  await page.waitForTimeout(400);
  await page.selectOption('#admin-user-status', 'active');
  await page.click('#btn-admin-user-apply');
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/ux-desktop-admin-users.png', fullPage: true });

  await page.click('#admin-nav-audit');
  await page.selectOption('#admin-audit-action', 'registration.approve');
  await page.click('#btn-admin-audit-apply');
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/ux-desktop-admin-audit.png', fullPage: true });

  const statusText = (await page.textContent('#status-line')) || '';
  const mailVisible = await page.locator('.mail-layout').count();
  const settingsVisible = await page.locator('.settings-layout').count();
  const adminVisible = await page.locator('.admin-layout').count();

  await browser.close();
  return { consoleErrors, dialogs, composeVisible, statusText, mailVisible, settingsVisible, adminVisible, initialTheme };
}

async function runMobile() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  const consoleErrors = [];
  const dialogs = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`));
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.type());
    await dialog.dismiss();
  });

  await page.goto('http://127.0.0.1:18081/', { waitUntil: 'networkidle' });
  const initialTheme = await page.locator('html').getAttribute('data-theme');
  await page.fill('#form-login input[name="email"]', 'admin@example.com');
  await page.fill('#form-login input[name="password"]', 'SecretPass123!');
  await page.click('#form-login button[type="submit"]');
  await page.waitForTimeout(1200);
  await page.click('#tab-mail');
  await page.waitForTimeout(600);

  const mobilePane = await page.locator('#view-mail').getAttribute('data-mobile-pane');
  await page.screenshot({ path: '/tmp/ux-mobile-mail.png', fullPage: true });

  await page.click('#tab-settings');
  await page.waitForTimeout(400);
  await page.screenshot({ path: '/tmp/ux-mobile-settings.png', fullPage: true });

  if ((await page.locator('.mailbox-list button').count()) > 0) {
    await page.click('#tab-mail');
    await page.waitForTimeout(240);
    await page.locator('.mailbox-list button').first().click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: '/tmp/ux-mobile-messages.png', fullPage: true });
    await page.click('#mail-mobile-back');
    await page.waitForTimeout(300);
  }

  await browser.close();
  return { consoleErrors, dialogs, mobilePane, initialTheme };
}

(async () => {
  const desktop = await runDesktop();
  const mobile = await runMobile();
  console.log(JSON.stringify({ desktop, mobile }, null, 2));
})();
