#!/usr/bin/env node

/**
 * Cloudflare Workaround Setup Script
 *
 * This script sets up a user with a TRUSTED browser profile to bypass
 * Cloudflare verification loops that occur with ephemeral contexts.
 */

const { AuthManager } = require('./playwright-session-manager');
const path = require('path');
const os = require('os');

function printBanner() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  CLOUDFLARE WORKAROUND - TRUSTED PROFILE SETUP         ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');
}

function printNextSteps(userId, profilePath) {
  console.log('\n╔════════════════════════════════════════════════════════╗');
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
  console.log(`  Run this command:`);
  console.log(`  chromium-browser --user-data-dir="${profilePath}" --no-sandbox --disable-dev-shm-usage\n`);
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
  console.log(`  3. Enter sequence details and user: ${userId}`);
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
}

function main() {
  printBanner();

  console.log('Step 1: Creating user configuration...\n');

  const authManager = new AuthManager();
  const userId = 'bob';
  const profilePath = path.join(os.homedir(), `.cf-trusted-profile-${userId}`);

  // Check if user already exists
  if (authManager.users.has(userId)) {
    const existingUser = authManager.users.get(userId);
    if (existingUser.browserProfile?.mode === 'trusted') {
      console.log(`✓ User "${userId}" already configured with TRUSTED profile mode`);
      console.log(`  Profile path: ${existingUser.browserProfile.path}\n`);

      printNextSteps(userId, existingUser.browserProfile.path);
      console.log(`Configuration saved to: ${authManager.usersFile}\n`);
      console.log('Ready to bootstrap! Follow Option A or B above.\n');
      return;
    }
  }

  // Add user with trusted profile
  authManager.addUser(userId, {
    email: `${userId}@example.com`,
    password: 'password123',
    browserProfile: {
      mode: 'trusted',
      path: profilePath
    }
  });

  console.log(`✓ User "${userId}" configured with TRUSTED profile mode`);
  console.log(`  Profile path: ${profilePath}\n`);

  printNextSteps(userId, profilePath);
  console.log(`Configuration saved to: ${authManager.usersFile}\n`);
  console.log('Ready to bootstrap! Follow Option A or B above.\n');
}

if (require.main === module) {
  main();
}

module.exports = { main };
