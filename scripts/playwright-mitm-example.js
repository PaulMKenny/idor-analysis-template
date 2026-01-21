/**
 * Example: Multi-user IDOR testing with mitmproxy capture
 *
 * This demonstrates the complete workflow:
 * 1. Start mitmproxy (captures traffic partitioned by action)
 * 2. Run Playwright tests for Alice
 * 3. Run Playwright tests for Bob (same actions, different user)
 * 4. Compare captured partitions to detect IDOR
 *
 * Before running:
 *   Terminal 1: mitmdump -s ../src/mitm_capture.py --listen-port 8080
 *   Terminal 2: npx playwright test playwright-mitm-example.js --headed
 */

const { test, expect } = require('@playwright/test');
const {
  ActionManager,
  mitmproxyConfig,
  checkMitmproxy
} = require('./playwright-mitm-integration');

// Configure all tests to use mitmproxy
test.use(mitmproxyConfig);

test.describe('Multi-user IDOR testing', () => {

  test.beforeEach(async ({ page }) => {
    // Verify mitmproxy is running
    const isRunning = await checkMitmproxy(page);
    if (!isRunning) {
      console.warn('\n⚠️  mitmproxy not detected at http://127.0.0.1:8080');
      console.warn('   Start it with: mitmdump -s ../src/mitm_capture.py --listen-port 8080\n');
    }
  });

  test('alice workflow', async ({ page }) => {
    const actions = new ActionManager(page, 'alice', 'session-1');

    // Action 1: Navigate to Wikipedia
    await actions.start('navigate to wikipedia');
    await page.goto('https://www.wikipedia.org/');
    await page.waitForLoadState('networkidle');

    // Action 2: Search for "IDOR"
    await actions.start('search for IDOR');
    await page.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('IDOR');
    await page.waitForTimeout(500);

    // Action 3: Submit search
    await actions.start('submit search');
    await page.getByRole('button', { name: 'Search' }).click();
    await page.waitForURL('**/wiki/**');

    console.log('\n✓ Alice workflow complete');
    console.log('  Partitions saved to: ui-automation/recordings/alice/session-1/\n');
  });

  test('bob workflow - same actions', async ({ page, browser }) => {
    const actions = new ActionManager(page, 'bob', 'session-1');

    // Same actions as Alice, but with Bob's context
    await actions.start('navigate to wikipedia');
    await page.goto('https://www.wikipedia.org/');
    await page.waitForLoadState('networkidle');

    await actions.start('search for IDOR');
    await page.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('IDOR');
    await page.waitForTimeout(500);

    await actions.start('submit search');
    await page.getByRole('button', { name: 'Search' }).click();
    await page.waitForURL('**/wiki/**');

    console.log('\n✓ Bob workflow complete');
    console.log('  Partitions saved to: ui-automation/recordings/bob/session-1/\n');
  });

  test('multi-user in single test', async ({ page, browser }) => {
    // Alice's workflow
    console.log('\n=== ALICE SESSION ===');
    const aliceActions = new ActionManager(page, 'alice', 'session-2');

    await aliceActions.start('open homepage');
    await page.goto('https://example.com');
    await page.waitForLoadState('networkidle');

    await aliceActions.start('click about');
    await page.click('a:has-text("More information")');
    await page.waitForLoadState('networkidle');

    // Bob's workflow (new context)
    console.log('\n=== BOB SESSION ===');
    const bobContext = await browser.newContext(mitmproxyConfig);
    const bobPage = await bobContext.newPage();
    const bobActions = new ActionManager(bobPage, 'bob', 'session-2');

    await bobActions.start('open homepage');
    await bobPage.goto('https://example.com');
    await bobPage.waitForLoadState('networkidle');

    await bobActions.start('click about');
    await bobPage.click('a:has-text("More information")');
    await bobPage.waitForLoadState('networkidle');

    await bobContext.close();

    console.log('\n✓ Multi-user test complete');
    console.log('  Alice: ui-automation/recordings/alice/session-2/');
    console.log('  Bob:   ui-automation/recordings/bob/session-2/');
    console.log('\n  Next: Use idor_interface.py to browse and compare partitions\n');
  });
});

test.describe('SaaS application testing (template)', () => {

  test.skip('login and access resources', async ({ page }) => {
    // Template for testing your own SaaS application
    const actions = new ActionManager(page, 'alice', 'session-1');

    // Login flow
    await actions.start('navigate to login');
    await page.goto('https://your-app.com/login');

    await actions.start('submit login');
    await page.fill('#email', 'alice@example.com');
    await page.fill('#password', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForURL('**/dashboard');

    // Resource access
    await actions.start('navigate to projects');
    await page.click('a:has-text("Projects")');
    await page.waitForLoadState('networkidle');

    await actions.start('open first project');
    await page.click('.project-list li:first-child');
    await page.waitForLoadState('networkidle');

    await actions.start('view documents');
    await page.click('button:has-text("Documents")');
    await page.waitForLoadState('networkidle');

    // Each action's HTTP traffic is now captured as a separate partition
  });
});
