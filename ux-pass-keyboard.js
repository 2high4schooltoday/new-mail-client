const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
  await page.goto('http://127.0.0.1:18081/', { waitUntil: 'networkidle' });
  const theme = await page.locator('html').getAttribute('data-theme');
  await page.fill('#form-login input[name="email"]', 'admin@example.com');
  await page.fill('#form-login input[name="password"]', 'SecretPass123!');
  await page.click('#form-login button[type="submit"]');
  await page.waitForTimeout(900);
  await page.click('#tab-mail');
  await page.waitForTimeout(500);

  await page.locator('#mailboxes').focus();
  const mailboxActiveDesc = await page.locator('#mailboxes').getAttribute('aria-activedescendant');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Escape');
  const paneAfterEsc = await page.locator('#view-mail').getAttribute('data-mobile-pane');
  const messageActiveDesc = await page.locator('#messages').getAttribute('aria-activedescendant');

  // ensure non-editable focus before compose shortcut
  await page.locator('#mail-pane-reader').focus();
  await page.keyboard.press('c');
  await page.waitForTimeout(200);
  const composeOpen = !(await page.locator('#compose-overlay').evaluate((n) => n.classList.contains('hidden')));
  if (composeOpen) {
    await page.keyboard.press('Escape');
  }

  await page.click('#tab-admin');
  await page.waitForTimeout(300);
  await page.click('#admin-nav-users');
  await page.waitForTimeout(250);
  const usersHidden = await page.locator('#admin-section-users').evaluate((n) => n.classList.contains('hidden'));
  const updateHidden = await page.locator('#admin-section-update').evaluate((n) => n.classList.contains('hidden'));

  console.log(JSON.stringify({ theme, paneAfterEsc, composeOpen, usersHidden, updateHidden, mailboxActiveDesc, messageActiveDesc }, null, 2));
  await browser.close();
})();
