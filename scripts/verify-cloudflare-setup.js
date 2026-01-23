#!/usr/bin/env node

/**
 * Cloudflare Setup Verification Script
 *
 * Verifies that users are properly configured with trusted profiles
 * and that the profiles have been bootstrapped with cookies.
 */

const { AuthManager } = require('./playwright-session-manager');
const fs = require('fs');
const path = require('path');

function printBanner() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  CLOUDFLARE SETUP VERIFICATION                         ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');
}

function printSummary(readyUsers) {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  SUMMARY                                               ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  if (readyUsers.length > 0) {
    console.log(`✓ ${readyUsers.length} user(s) ready for Cloudflare sites: ${readyUsers.join(', ')}\n`);
    console.log('  You can now record on GitLab without Cloudflare loops!');
    console.log('  Recording mode will automatically use the trusted profile.\n');
  } else {
    console.log('❌ No users are ready for Cloudflare sites.\n');
    console.log('  Setup a trusted profile:');
    console.log('    1. npm run setup:cloudflare');
    console.log('    2. npm run cli → Bootstrap Trusted Profile\n');
  }
}

function formatBytes(bytes) {
  return `${(bytes / 1024).toFixed(0)}KB`;
}

function main() {
  printBanner();

  const authManager = new AuthManager();
  const userIds = authManager.getUserIds();

  if (userIds.length === 0) {
    console.log('❌ No users configured.\n');
    console.log('  Run: npm run setup:cloudflare\n');
    return;
  }

  console.log(`✓ Found ${userIds.length} user(s): ${userIds.join(', ')}\n`);

  const readyUsers = [];

  userIds.forEach(userId => {
    const user = authManager.users.get(userId);
    const profileConfig = user.browserProfile || { mode: 'managed' };

    console.log(`User: ${userId}`);
    console.log(`  Mode: ${profileConfig.mode}`);

    if (profileConfig.mode === 'managed') {
      const profilePath = authManager.getProfilePath(userId);
      console.log(`  Profile: ${profilePath}`);
      console.log(`  Status: ⚠️  MANAGED mode (may trigger Cloudflare loops)\n`);
      console.log('  Recommendation: Switch to TRUSTED mode');
      console.log('    1. npm run cli');
      console.log('    2. Configure Users → Configure Browser Profile Mode');
      console.log('    3. Select user and choose "Trusted" mode\n');
    } else if (profileConfig.mode === 'trusted') {
      const profilePath = profileConfig.path;
      console.log(`  Profile: ${profilePath}`);

      // Check if profile directory exists
      if (!fs.existsSync(profilePath)) {
        console.log(`  Status: ❌ Profile directory does NOT exist\n`);
        console.log('  Action required: Bootstrap the profile');
        console.log('    npm run cli → Bootstrap Trusted Profile\n');
        return;
      }

      console.log(`  Status: ✓ Profile directory exists`);

      // Check for cookies using the AuthManager's helper method
      const cookieCheck = authManager.checkProfileCookies(profilePath);

      if (cookieCheck.hasCookies) {
        console.log(`  Cookies: ✓ Found (profile appears bootstrapped)`);
        console.log(`  Cookie DB: ${formatBytes(cookieCheck.cookieDbSize)}\n`);
        console.log('  ✓ This profile is READY for Cloudflare-protected sites');
        console.log('    It likely contains cf_clearance cookies\n');
        readyUsers.push(userId);
      } else {
        console.log(`  Cookies: ❌ Not found or empty database\n`);
        console.log('  Action required: Bootstrap the profile');
        console.log('    1. npm run cli');
        console.log('    2. Select: 8. Bootstrap Trusted Profile');
        console.log('    3. Navigate to GitLab and solve Cloudflare challenges');
        console.log('    4. Close browser when done\n');
      }
    }
  });

  printSummary(readyUsers);
}

if (require.main === module) {
  main();
}

module.exports = { main };
