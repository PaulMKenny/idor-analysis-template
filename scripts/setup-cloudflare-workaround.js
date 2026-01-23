#!/usr/bin/env node
/**
 * Automated setup for Cloudflare-bypassing trusted profiles
 *
 * This script:
 * 1. Creates users with trusted profile mode
 * 2. Provides instructions for bootstrapping profiles
 * 3. Configures the system for GitLab/Cloudflare-protected sites
 */

const { AuthManager } = require('./playwright-session-manager');
const path = require('path');
const os = require('os');

async function setup() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  CLOUDFLARE WORKAROUND - TRUSTED PROFILE SETUP         ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  const authManager = new AuthManager();
  const currentUser = os.userInfo().username;

  // Configure user 'bob' with trusted profile
  const userId = 'bob';
  const trustedProfilePath = `/home/${currentUser}/.cf-trusted-profile-${userId}`;

  console.log('Step 1: Creating user configuration...\n');

  authManager.addUser(userId, {
    email: 'bob@example.com',
    password: 'bobpassword123',
    browserProfile: {
      mode: 'trusted',
      path: trustedProfilePath
    }
  });

  console.log(`✓ User "${userId}" configured with TRUSTED profile mode`);
  console.log(`  Profile path: ${trustedProfilePath}\n`);

  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  NEXT STEPS - BOOTSTRAP THE TRUSTED PROFILE           ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  console.log('You have two options:\n');

  console.log('OPTION A - Use the CLI (Recommended):');
  console.log('  1. Run: npm run cli');
  console.log('  2. Select: 8. Bootstrap Trusted Profile');
  console.log('  3. Follow on-screen instructions to:');
  console.log('     - Solve Cloudflare challenges on GitLab');
  console.log('     - Optionally log in to GitLab');
  console.log('     - Browse a few pages');
  console.log('  4. Close browser when done\n');

  console.log('OPTION B - Manual Bootstrap:');
  console.log('  Run this command:');
  console.log(`  chromium-browser --user-data-dir="${trustedProfilePath}" --no-sandbox --disable-dev-shm-usage\n`);
  console.log('  Then:');
  console.log('  1. Navigate to https://gitlab.com/users/sign_in');
  console.log('  2. Solve any Cloudflare challenges');
  console.log('  3. Optionally log in to GitLab');
  console.log('  4. Browse a few pages (explore, projects, etc.)');
  console.log('  5. Close the browser\n');

  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  AFTER BOOTSTRAPPING                                   ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  console.log('Your recording mode will automatically use the trusted profile!');
  console.log('The profile contains:');
  console.log('  ✓ Cloudflare clearance cookies (cf_clearance)');
  console.log('  ✓ Browser fingerprint (trusted by Cloudflare)');
  console.log('  ✓ localStorage/sessionStorage');
  console.log('  ✓ Login session (if you logged in)\n');

  console.log('To record a sequence on GitLab:');
  console.log('  1. npm run cli');
  console.log('  2. Select: 3. Record New Sequence');
  console.log('  3. Enter sequence details and user: bob');
  console.log('  4. Run: npx playwright test --grep "record-mode"\n');

  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  WHY THIS WORKS                                        ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  console.log('Cloudflare verification loops happen because:');
  console.log('  ❌ Ephemeral contexts reset cookies/TLS fingerprint');
  console.log('  ❌ "Managed" mode creates fresh, untrusted profiles');
  console.log('  ❌ Playwright\'s default browser is detected\n');

  console.log('Trusted profiles solve this by:');
  console.log('  ✓ Preserving Cloudflare clearance across sessions');
  console.log('  ✓ Using a manually-vetted browser profile');
  console.log('  ✓ Stable TLS fingerprint and browser entropy');
  console.log('  ✓ Stealth scripts hide automation signals\n');

  console.log('Configuration saved to: ./auth-sessions/users.json\n');
  console.log('Ready to bootstrap! Follow Option A or B above.\n');
}

if (require.main === module) {
  setup().catch(console.error);
}

module.exports = { setup };
