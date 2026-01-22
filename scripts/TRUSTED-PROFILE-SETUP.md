# Trusted Profile Setup Guide

## Quick Start: GitLab Cloudflare Issue

If you're experiencing Cloudflare verification loops on GitLab (or any strict Cloudflare-protected site), follow this guide.

---

## Step-by-Step Setup

### 1. Configure User with Trusted Mode

```bash
cd scripts
npm run cli
```

In the CLI menu:
```
Main Menu
→ 1. Configure Users
→ 3. Configure Browser Profile Mode
→ User ID: bob
→ Mode: 2 (Trusted)
→ Path: /home/user/.cf-trusted-profile-bob
```

**Result:** User `bob` is now configured to use a trusted profile.

---

### 2. Bootstrap the Trusted Profile

Still in the CLI:
```
Main Menu
→ 8. Bootstrap Trusted Profile
→ Select user: 1 (bob)
→ Press Enter
```

**What happens:**
- Chromium browser window opens
- You see the profile path in terminal

**What to do manually:**
1. ✅ Navigate to https://gitlab.com/users/sign_in
2. ✅ Solve Cloudflare challenge (checkbox or wait)
3. ✅ Log into GitLab with your credentials
4. ✅ Browse 2-3 pages (Projects, Groups, etc.)
5. ✅ Close the browser window normally

**Important:** Don't kill the process, close it naturally.

---

### 3. Verify Setup

Check the profile was created:
```bash
ls -la /home/user/.cf-trusted-profile-bob/
```

You should see:
```
Cookies
Local Storage
Session Storage
History
...
```

Check user config:
```bash
cat scripts/auth-sessions/users.json
```

Should show:
```json
{
  "users": {
    "bob": {
      "email": "bob@example.com",
      "password": "your-password",
      "browserProfile": {
        "mode": "trusted",
        "path": "/home/user/.cf-trusted-profile-bob"
      }
    }
  }
}
```

---

### 4. Use in Tests

Now when you run your Playwright tests with user `bob`, it will automatically use the trusted profile:

```javascript
const { chromium } = require('playwright');
const { AuthManager } = require('./playwright-session-manager');

const authManager = new AuthManager();

// This now uses the trusted profile automatically
const context = await authManager.launchUserContext(chromium, 'bob');
const page = context.pages()[0] || await context.newPage();

await page.goto('https://gitlab.com/explore');
// ✅ No Cloudflare loop!
// ✅ Already logged in!
// ✅ Ready to test immediately
```

---

## Why This Works

| Approach | Cloudflare Sees |
|----------|-----------------|
| **Managed Mode** | New browser profile → No history → Challenge every time |
| **Trusted Mode** | Known browser profile → History exists → Trust established |

Cloudflare doesn't just check cookies. It checks:
- Browser history
- Canvas/WebGL fingerprints
- LocalStorage artifacts
- Prior challenge solves
- Browsing patterns

A manually-bootstrapped profile has all of these. A Playwright-created profile doesn't.

---

## Troubleshooting

### Still Getting Cloudflare Loops?

**Check #1: Profile exists**
```bash
ls /home/user/.cf-trusted-profile-bob/
```
If empty or missing → re-run bootstrap

**Check #2: Correct Chromium executable**
```bash
which chromium-browser
# Should be: /usr/bin/chromium-browser
```

**Check #3: You actually logged in during bootstrap**
- Did you complete the login?
- Did you browse a few pages?
- Did you close normally (not kill)?

**Check #4: No proxy interference**
```bash
env | grep -i proxy
# Should be empty
```

If proxy is set:
```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
```

### Error: "Trusted profile not found"

This means:
- Profile path is wrong in `users.json`, OR
- Profile wasn't created during bootstrap

**Fix:**
1. Run bootstrap again
2. Verify path matches exactly

### Browser Opens But Still Shows Challenge

This is normal **on first use**.

**Expected flow:**
1. Bootstrap → Manual challenge solve → Close
2. First automation run → May show challenge once more
3. Second+ automation runs → No challenge

If challenge persists after 2+ runs:
- Profile might not have saved properly
- Delete and re-bootstrap

---

## Per-User vs Global Profiles

### ✅ Recommended: Per-User Profiles

```
/home/user/.cf-trusted-profile-bob/    # Bob's GitLab
/home/user/.cf-trusted-profile-alice/  # Alice's GitLab
```

**Why:**
- Each user has independent session
- Matches real multi-user testing
- No cross-contamination

### ❌ Not Recommended: Shared Profile

Don't use the same profile for multiple users:
```
# BAD: bob and alice both use this
/home/user/.cf-shared-profile/
```

Cloudflare will see session switching → suspicious → more challenges.

---

## When to Use Trusted Mode

| Site/Scenario | Recommended Mode |
|---------------|------------------|
| GitLab | Trusted |
| Strict Cloudflare sites | Trusted |
| Bug bounty targets | Trusted |
| Production SaaS apps | Trusted |
| Internal tools | Managed |
| Light Cloudflare | Managed |
| First-time setup | Managed (upgrade if loops occur) |

**Rule of thumb:**
- Start with managed mode
- If you get verification loops → upgrade to trusted

---

## Summary

1. **Configure** user with trusted mode via CLI
2. **Bootstrap** profile manually (one time)
3. **Use** in tests automatically (no code changes)
4. **Enjoy** no more Cloudflare loops

The trusted profile approach is:
- ✅ Architecturally sound
- ✅ One-time setup
- ✅ Zero maintenance
- ✅ Works for strictest Cloudflare configs

This is not a hack or workaround. This is **how real browsers work**.
