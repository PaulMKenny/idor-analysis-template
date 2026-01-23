#!/bin/bash
#
# Bootstrap Trusted Profile for Cloudflare Bypass
#
# This script launches Chromium with a trusted profile.
# You will manually:
# 1. Solve Cloudflare challenges on GitLab
# 2. Optionally log in to GitLab
# 3. Browse a few pages
# 4. Close browser when done
#

USER_ID="${1:-bob}"
PROFILE_PATH="/home/$USER/.cf-trusted-profile-$USER_ID"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  BOOTSTRAPPING TRUSTED PROFILE: $USER_ID"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Profile path: $PROFILE_PATH"
echo ""
echo "=== INSTRUCTIONS ==="
echo "1. Solve any Cloudflare challenges"
echo "2. Log into GitLab (optional but recommended)"
echo "3. Browse a few pages (explore, projects, etc.)"
echo "4. Close the browser window when done"
echo "===================="
echo ""
echo "Launching Chromium in 3 seconds..."
sleep 3

# Create profile directory if it doesn't exist
mkdir -p "$PROFILE_PATH"

# Launch Chromium with the trusted profile
chromium-browser \
  --user-data-dir="$PROFILE_PATH" \
  --no-sandbox \
  --disable-dev-shm-usage \
  --disable-blink-features=AutomationControlled \
  --disable-features=IsolateOrigins,site-per-process \
  --exclude-switches=enable-automation \
  'https://gitlab.com/users/sign_in'

echo ""
echo "✓ Bootstrap complete!"
echo ""
echo "Run verification:"
echo "  cd scripts && npm run verify:cloudflare"
echo ""
