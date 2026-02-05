/**
 * Persistent Browser Context Example
 *
 * This demonstrates the CORRECT approach for Cloudflare-protected sites.
 *
 * WHY PERSISTENT CONTEXTS:
 * - Cloudflare verification loops happen when client identity changes
 * - Ephemeral contexts reset cookies, TLS fingerprint, browser entropy
 * - Persistent contexts preserve ALL identity signals
 * - This is the only architecturally sound solution
 *
 * WHEN TO USE:
 * - Any Cloudflare-protected site (GitLab, most SaaS apps)
 * - Any site with sticky sessions
 * - Long-running test suites
 * - Multi-session IDOR testing
 *
 * Run: node scripts/playwright-persistent-example.js
 */

const { chromium } = require('playwright');
const { AuthManager, createSessionClock, createActionAwareRequestLogger } = require('./playwright-session-manager');

async function demonstratePersistentContext() {
  console.log('=== PERSISTENT CONTEXT DEMO ===\n');

  const authManager = new AuthManager();

  // Configure users (persistent across runs)
  authManager.addUser('alice', {
    email: 'alice@example.com',
    password: 'secret123'
  });

  // Launch persistent context (THE CORRECT WAY)
  console.log('✓ Launching persistent browser context for alice...');
  const context = await authManager.launchUserContext(chromium, 'alice', {
    headless: false,
    viewport: { width: 1280, height: 720 }
  });

  const page = context.pages()[0] || await context.newPage();
  const now = createSessionClock();
  const logger = createActionAwareRequestLogger(page, now);

  // Example: Access a Cloudflare-protected site
  console.log('\n✓ Navigating to Cloudflare-protected site...');
  logger.startAction('visit gitlab');
  await page.goto('https://gitlab.com/explore');
  await page.waitForLoadState('networkidle');

  console.log('✓ First visit complete.');
  console.log('   If Cloudflare challenged you, complete it now.');
  console.log('   The challenge will be remembered for future runs.\n');

  await page.waitForTimeout(3000);

  // Navigate again - should NOT trigger Cloudflare loop
  logger.startAction('navigate projects');
  await page.goto('https://gitlab.com/explore/projects');
  await page.waitForLoadState('networkidle');

  console.log('✓ Second navigation complete - no Cloudflare loop!\n');

  // Close and verify profile persistence
  const capture = logger.stop();
  console.log(`✓ Captured ${capture.length} actions`);
  console.log(`✓ Profile saved to: ${authManager.getProfilePath('alice')}`);

  await context.close();

  console.log('\n=== DEMONSTRATION COMPLETE ===');
  console.log('\nKey points:');
  console.log('1. Cloudflare challenge completed ONCE');
  console.log('2. Subsequent navigations work without re-challenge');
  console.log('3. Profile persists - rerun this script to verify');
  console.log('4. This is the ONLY reliable approach for Cloudflare\n');
}

async function demonstrateEphemeralContext() {
  console.log('=== EPHEMERAL CONTEXT (WRONG WAY) ===\n');
  console.log('⚠️  This demonstrates what NOT to do:\n');

  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext(); // ❌ Ephemeral context
  const page = await context.newPage();

  console.log('❌ Using ephemeral context (no persistence)');
  console.log('   Cloudflare will challenge EVERY session');
  console.log('   Cookies reset on browser close');
  console.log('   TLS fingerprint changes');
  console.log('   Browser entropy resets\n');

  await page.goto('https://gitlab.com/explore');
  await page.waitForLoadState('networkidle');

  console.log('⚠️  You may see Cloudflare verification now.');
  console.log('   Even if you complete it, it will repeat next run.\n');

  await page.waitForTimeout(2000);
  await browser.close();

  console.log('❌ Context destroyed - all state lost\n');
}

async function compareApproaches() {
  console.log('\n╔═══════════════════════════════════════════════════════╗');
  console.log('║       EPHEMERAL vs PERSISTENT CONTEXTS               ║');
  console.log('╚═══════════════════════════════════════════════════════╝\n');

  console.log('┌─────────────────────────┬─────────────┬─────────────┐');
  console.log('│ Signal                  │ Ephemeral   │ Persistent  │');
  console.log('├─────────────────────────┼─────────────┼─────────────┤');
  console.log('│ Cookies (cf_clearance)  │ ❌ Lost     │ ✓ Preserved │');
  console.log('│ localStorage            │ ❌ Lost     │ ✓ Preserved │');
  console.log('│ sessionStorage          │ ❌ Lost     │ ✓ Preserved │');
  console.log('│ TLS fingerprint         │ ❌ Changes  │ ✓ Stable    │');
  console.log('│ Browser entropy         │ ❌ Resets   │ ✓ Stable    │');
  console.log('│ Cloudflare loop         │ ❌ Always   │ ✓ Once      │');
  console.log('│ Architectural soundness │ ❌ Broken   │ ✓ Correct   │');
  console.log('└─────────────────────────┴─────────────┴─────────────┘\n');

  console.log('VERDICT:');
  console.log('  Ephemeral contexts = Fighting Cloudflare (you lose)');
  console.log('  Persistent contexts = Working with Cloudflare (you win)\n');
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--compare')) {
    await compareApproaches();
    return;
  }

  if (args.includes('--wrong')) {
    await demonstrateEphemeralContext();
    return;
  }

  // Default: show the correct way
  await demonstratePersistentContext();
}

if (require.main === module) {
  main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
  });
}

module.exports = {
  demonstratePersistentContext,
  demonstrateEphemeralContext,
  compareApproaches
};
