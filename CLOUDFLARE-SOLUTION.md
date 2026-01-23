# Cloudflare Bypass Solution for GitLab Recording

## Problem

When recording sessions on Cloudflare-protected sites like GitLab, you encounter:
- 403 Forbidden responses
- "Just a moment..." Cloudflare challenge pages
- Endless verification loops
- Blocked automation detection

## Root Cause

Cloudflare detects automation through:
1. **Ephemeral browser contexts** - Reset cookies/TLS fingerprints
2. **Fresh browser profiles** - No trust history
3. **Automation signals** - `navigator.webdriver`, missing plugins, etc.
4. **Inconsistent client identity** - Changes between sessions

## Solution: Trusted Profile Mode

We use **persistent browser contexts** with **pre-bootstrapped profiles** that have:
- ✓ Cloudflare clearance cookies (`cf_clearance`)
- ✓ Established browser fingerprint
- ✓ localStorage/sessionStorage state
- ✓ Stable TLS fingerprint
- ✓ Stealth scripts to hide automation

## Quick Start

### Step 1: Setup (One-Time)

```bash
cd scripts
npm run setup:cloudflare
```

This creates user `bob` with trusted profile mode at:
`/home/YOUR_USER/.cf-trusted-profile-bob`

### Step 2: Bootstrap the Profile (One-Time)

**Option A - Automated Bootstrap (Recommended):**
```bash
cd scripts
npm run bootstrap:profile
```

**Option B - Manual Bootstrap:**
```bash
chromium-browser --user-data-dir="/home/YOUR_USER/.cf-trusted-profile-bob" \
  --no-sandbox --disable-dev-shm-usage \
  --disable-blink-features=AutomationControlled
```

Then:
1. Navigate to https://gitlab.com/users/sign_in
2. **Solve Cloudflare challenge** (checkbox/CAPTCHA)
3. **Log in to GitLab** (optional but recommended)
4. Browse a few pages (explore, projects, etc.)
5. **Close the browser**

### Step 3: Verify Setup

```bash
cd scripts
npm run verify:cloudflare
```

You should see:
```
✓ User bob configured with TRUSTED profile mode
✓ Profile directory exists
✓ Cookies found (profile appears bootstrapped)
✓ This profile is READY for Cloudflare-protected sites
```

### Step 4: Record on GitLab (No More Cloudflare!)

```bash
cd scripts
npm run cli
```

Select:
1. **3. Record New Sequence**
2. Enter name: `gitlab-test`
3. Enter user: `bob` ← **Uses trusted profile automatically!**

Then:
```bash
npx playwright test --grep "record-mode" --headed
```

The browser will:
- ✓ Use your bootstrapped profile
- ✓ Skip Cloudflare challenges
- ✓ Stay logged in
- ✓ Record all HTTP traffic

## How It Works

### Architecture

```
┌─────────────────────────────────────┐
│  Recording Mode (Playwright Test)  │
│                                     │
│  authManager.launchUserContext()    │
│         ↓                           │
│  Checks: user.browserProfile.mode   │
└─────────────────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
┌───▼───┐              ┌─────▼─────┐
│MANAGED│              │  TRUSTED  │
│ Mode  │              │   Mode    │
└───┬───┘              └─────┬─────┘
    │                        │
    │ Fresh profile          │ Pre-bootstrapped
    │ No Cloudflare          │ Has cf_clearance
    │ ❌ Gets blocked        │ ✓ Bypasses Cloudflare
    │                        │
    ▼                        ▼
```

### Managed vs Trusted Mode

| Feature | Managed | Trusted |
|---------|---------|---------|
| Profile location | `auth-sessions/browser-profiles/bob` | `/home/user/.cf-trusted-profile-bob` |
| Created by | Playwright (ephemeral) | You (manual bootstrap) |
| Cloudflare trust | ❌ None (gets blocked) | ✓ Pre-established |
| Cookies persist | ✓ Yes | ✓ Yes |
| Manual setup | ❌ No | ✓ Yes (one-time) |
| Best for | Local testing | Cloudflare sites |

### Stealth Measures

The `launchUserContext()` function in `playwright-session-manager.js` applies stealth scripts:

```javascript
// Override navigator.webdriver
Object.defineProperty(navigator, 'webdriver', {
  get: () => undefined
});

// Remove Chrome automation signals
delete window.chrome.runtime;

// Override permissions query
window.navigator.permissions.query = ...

// Add plugins to appear human
Object.defineProperty(navigator, 'plugins', {
  get: () => [1, 2, 3, 4, 5]
});
```

These hide automation from Cloudflare's JavaScript checks.

## Troubleshooting

### "Profile directory does NOT exist"

Run bootstrap:
```bash
cd scripts
npm run bootstrap:profile
```

### "No cookies found (profile NOT bootstrapped)"

You need to manually complete Cloudflare:
1. Run bootstrap script
2. **Solve the Cloudflare challenge**
3. Browse a few pages
4. Close browser

### Still getting Cloudflare loops?

Check:
1. User is configured with `mode: trusted` (run `verify:cloudflare`)
2. Profile was actually bootstrapped (check for Cookies file)
3. You're using the correct user ID in recording
4. Browser hasn't cleared the profile

### Testing the Bootstrap

To test if your profile works:
```bash
cd scripts
npm run demo:persistent
```

This should:
- Open GitLab without Cloudflare challenge
- Navigate to explore page
- No verification loops

## Why This Is The Only Reliable Solution

### ❌ What Doesn't Work

**1. Stealth libraries alone (Puppeteer Extra, undetected-chromedriver)**
- Cloudflare has server-side checks
- Can detect even perfect browser mimicry
- TLS fingerprints still change per session

**2. Cookie injection**
- `cf_clearance` cookies are bound to TLS session
- Injecting cookies without matching TLS = invalid
- Results in verification loop

**3. Ephemeral contexts with stealth**
- Browser fingerprint changes
- Cloudflare notices inconsistencies
- Still triggers verification

### ✓ What Works (This Solution)

**Persistent contexts + Manual bootstrap:**
- One human interaction establishes trust
- All future sessions reuse the EXACT same identity
- TLS fingerprint stable
- Cookies valid
- No detection

This is **architecturally sound** because:
1. We're not fighting Cloudflare, we're working with it
2. The profile is genuinely trusted (human-verified once)
3. Subsequent automation is indistinguishable from returning visitor

## Advanced Usage

### Multiple Users for IDOR Testing

Create additional users:
```bash
cd scripts
npm run cli
```

Select: `1. Configure Users → 1. Add User`

Add users: `alice`, `charlie`, etc.

Then configure each with trusted profile:
`1. Configure Users → 3. Configure Browser Profile Mode`

Bootstrap each:
```bash
npm run bootstrap:profile alice
npm run bootstrap:profile charlie
```

### Using Existing Chromium Profiles

If you already have a Chromium profile with GitLab logged in:

```javascript
authManager.addUser('myuser', {
  email: 'myuser@example.com',
  password: 'pass',
  browserProfile: {
    mode: 'trusted',
    path: '/home/myuser/.config/chromium/Default'
  }
});
```

**Warning:** Only use throwaway profiles for testing, as Playwright may modify them.

### Debugging Profile Issues

List all cookies in profile:
```bash
sqlite3 /home/user/.cf-trusted-profile-bob/Default/Cookies \
  "SELECT name, host_key FROM cookies WHERE name LIKE '%cf%';"
```

Look for:
- `cf_clearance` (Cloudflare challenge completion)
- `__cf_bm` (Cloudflare bot management)

## Technical Details

### Cloudflare Challenge Flow

Without trusted profile:
```
1. Playwright → GET https://gitlab.com/users/sign_in
2. Cloudflare → 403 Forbidden (cf-mitigated: challenge)
3. Browser → Loads Turnstile challenge
4. JavaScript → Collects fingerprints, sends to Cloudflare
5. Cloudflare → Verifies fingerprints
6. Cloudflare → Issues cf_clearance cookie
7. Playwright → Continues to GitLab
8. [Next session] → Repeat from step 1 (cookies lost!)
```

With trusted profile:
```
1. [Bootstrap] Human solves challenge once
2. cf_clearance saved to persistent profile
3. Playwright → Launches with existing profile
4. Playwright → GET https://gitlab.com/users/sign_in
5. Cloudflare → Recognizes cf_clearance + TLS fingerprint
6. Cloudflare → ✓ Allows request
7. GitLab → Responds normally
8. [Next session] → Reuses same profile (cookies persist!)
```

### TLS Fingerprinting

Cloudflare uses TLS fingerprints (JA3) to track clients:
- Cipher suites
- TLS extensions
- Handshake order

Ephemeral contexts generate **different JA3 hashes** each time.
Persistent contexts maintain **stable JA3 hashes**.

### Detection Signals Cloudflare Checks

From your transaction data, Cloudflare checks:
- `sec-ch-ua-*` headers (Chrome client hints)
- `user-agent` consistency
- `accept-language` patterns
- JavaScript challenges (WebGL, Canvas, Audio)
- Mouse/keyboard timing
- WebRTC leaks
- Browser entropy (fonts, plugins, screen)

Trusted profiles pass all checks because they're genuinely human-bootstrapped.

## References

- Video 1: Selenium Base CDP mode (similar approach)
- Video 2: NoDriver cookie export (related technique)
- Video 3: Patched-Playwright (alternative stealth library)
- `playwright-persistent-example.js` - Live demo
- `playwright-session-manager.js` - Implementation (lines 156-246)

## Summary

**Problem:** Cloudflare blocks Playwright automation
**Root cause:** Ephemeral contexts reset client identity
**Solution:** Persistent contexts with manual bootstrap
**Result:** One-time human verification, infinite automated sessions

---

**Setup:** `npm run setup:cloudflare`
**Bootstrap:** `npm run bootstrap:profile`
**Verify:** `npm run verify:cloudflare`
**Record:** Use `bob` as user ID in recording mode

✓ No more Cloudflare loops!
