#!/bin/bash

##
# Bootstrap Trusted Profile Script
#
# This script launches Chromium with a trusted profile for manual bootstrapping.
# Use this to solve Cloudflare challenges and establish browser trust.
##

# Default user
USER_ID=${1:-bob}
PROFILE_PATH="${HOME}/.cf-trusted-profile-${USER_ID}"

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  BOOTSTRAPPING TRUSTED PROFILE: ${USER_ID}"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Profile path: ${PROFILE_PATH}"
echo ""

# Create profile directory if it doesn't exist
if [ ! -d "${PROFILE_PATH}" ]; then
  echo "Creating profile directory: ${PROFILE_PATH}"
  mkdir -p "${PROFILE_PATH}"
fi

echo "=== INSTRUCTIONS ==="
echo "1. Solve any Cloudflare challenges"
echo "2. Log into GitLab (optional but recommended)"
echo "3. Browse a few pages (explore, projects, etc.)"
echo "4. Close the browser window when done"
echo "===================="
echo ""
echo "Launching Chromium in 3 seconds..."
sleep 3

# Launch Chromium with the trusted profile
chromium-browser \
  --user-data-dir="${PROFILE_PATH}" \
  --no-sandbox \
  --disable-dev-shm-usage \
  2>&1 | grep -E "(ERROR|WARNING)" | head -20 || true

echo ""
echo "✓ Bootstrap complete!"
echo ""
echo "Run verification:"
echo "  cd scripts && npm run verify:cloudflare"
echo ""
