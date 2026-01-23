#!/usr/bin/env node
/**
 * Verify Cloudflare workaround setup
 *
 * Checks:
 * - User configuration
 * - Trusted profile existence
 * - Cookie presence
 */

const { AuthManager } = require('./playwright-session-manager');
const fs = require('fs');
const path = require('path');

async function verify() {
  console.log('\n╔════════════════════════════════════════════════════════╗');
  console.log('║  CLOUDFLARE SETUP VERIFICATION                         ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  const authManager = new AuthManager();
  const userIds = authManager.getUserIds();

  if (userIds.length === 0) {
    console.log('❌ No users configured\n');
    console.log('   Run: node scripts/setup-cloudflare-workaround.js\n');
    return;
  }

  console.log(`✓ Found ${userIds.length} user(s): ${userIds.join(', ')}\n`);

  // Check each user
  for (const userId of userIds) {
    const user = authManager.users.get(userId);
    const profileMode = user.browserProfile?.mode || 'managed';

    console.log(`User: ${userId}`);
    console.log(`  Mode: ${profileMode}`);

    if (profileMode === 'trusted') {
      const profilePath = user.browserProfile.path;
      console.log(`  Profile: ${profilePath}`);

      // Check if profile exists
      if (fs.existsSync(profilePath)) {
        console.log('  Status: ✓ Profile directory exists');

        // Check for cookies file (Chromium stores cookies in a SQLite database)
        const cookiesPath = path.join(profilePath, 'Default', 'Cookies');
        const networkPath = path.join(profilePath, 'Default', 'Network');

        if (fs.existsSync(cookiesPath) || fs.existsSync(networkPath)) {
          console.log('  Cookies: ✓ Found (profile appears bootstrapped)');

          // Check file sizes
          try {
            if (fs.existsSync(cookiesPath)) {
              const stats = fs.statSync(cookiesPath);
              console.log(`  Cookie DB: ${Math.round(stats.size / 1024)}KB`);
            }
          } catch (e) {
            // Ignore
          }

          console.log('\n  ✓ This profile is READY for Cloudflare-protected sites');
          console.log('    It likely contains cf_clearance cookies\n');

        } else {
          console.log('  Cookies: ❌ Not found (profile NOT bootstrapped)');
          console.log('\n  ⚠️  This profile needs bootstrapping!');
          console.log('      Run: npm run cli → 8. Bootstrap Trusted Profile\n');
        }

      } else {
        console.log('  Status: ❌ Profile directory does NOT exist');
        console.log('\n  ⚠️  Bootstrap required!');
        console.log('      Run: npm run cli → 8. Bootstrap Trusted Profile\n');
      }

    } else if (profileMode === 'managed') {
      const managedPath = authManager.getProfilePath(userId);
      console.log(`  Profile: ${managedPath}`);
      console.log('  Status: ⚠️  MANAGED mode (may trigger Cloudflare loops)');
      console.log('\n  Recommendation: Switch to TRUSTED mode');
      console.log('    1. npm run cli');
      console.log('    2. Configure Users → Configure Browser Profile Mode');
      console.log('    3. Select user and choose "Trusted" mode\n');
    }
  }

  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  SUMMARY                                               ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  const trustedUsers = userIds.filter(id => {
    const user = authManager.users.get(id);
    return user.browserProfile?.mode === 'trusted' &&
           fs.existsSync(user.browserProfile.path);
  });

  if (trustedUsers.length > 0) {
    console.log(`✓ ${trustedUsers.length} user(s) ready for Cloudflare sites: ${trustedUsers.join(', ')}`);
    console.log('\n  You can now record on GitLab without Cloudflare loops!');
    console.log('  Recording mode will automatically use the trusted profile.\n');
  } else {
    console.log('❌ No users have bootstrapped trusted profiles');
    console.log('\n  To fix:');
    console.log('    1. Run: node scripts/setup-cloudflare-workaround.js');
    console.log('    2. Follow bootstrap instructions');
    console.log('    3. Re-run this verification\n');
  }
}

if (require.main === module) {
  verify().catch(console.error);
}

module.exports = { verify };
