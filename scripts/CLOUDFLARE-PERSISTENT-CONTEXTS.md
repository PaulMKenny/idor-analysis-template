# Cloudflare Verification Loops & Persistent Browser Contexts

## The Problem

When testing Cloudflare-protected sites (GitLab, most SaaS applications), you may encounter **infinite verification loops** where Cloudflare repeatedly asks you to verify you're human.

This is **not a bug**. It's Cloudflare working exactly as designed.

## Why Verification Loops Happen

Cloudflare verifies **client identity continuity**, not just "did you solve the challenge once."

A client is identified by:

| Signal | Ephemeral Context | Persistent Context |
|--------|------------------|-------------------|
| **Cookies** (cf_clearance) | ❌ Reset every session | ✓ Preserved |
| **localStorage** | ❌ Reset every session | ✓ Preserved |
| **sessionStorage** | ❌ Reset every session | ✓ Preserved |
| **TLS fingerprint** | ❌ Changes | ✓ Stable |
| **Browser entropy** | ❌ Resets | ✓ Stable |
| **IP stability** | Depends on network | Depends on network |

If **any** of these reset → Cloudflare challenges again.

## Common Triggers in Your Setup

### 1. Ephemeral Browser Contexts (Most Common)

```javascript
// ❌ WRONG: Creates new context every time
const browser = await chromium.launch();
const context = await browser.newContext(); // All state lost on close
```

### 2. MITM Proxies (Burp / mitmproxy)

Cloudflare is **extremely** sensitive to:
- TLS man-in-the-middle
- HTTP/2 downgrades
- Modified headers
- Timing anomalies

**Fix**: Exclude GitLab/tooling domains from proxy (proxy only target sites).

### 3. Playwright Automation Fingerprints

Cloudflare detects:
- `navigator.webdriver`
- Headless mode indicators
- Missing browser entropy
- Chromium automation quirks

**Mitigation**: Use headed mode, persistent contexts.

### 4. Kali Linux Fingerprint

Kali has non-standard:
- Font rendering
- GPU stack
- TLS ciphers
- Kernel timing

**Result**: Higher challenge frequency.

### 5. VPN / Hosting IP

VPNs, VPS, cloud providers → lower IP reputation → more challenges.

## The Solution: Persistent Browser Contexts

### What Are Persistent Contexts?

Persistent contexts are **stateful browser profiles** that preserve all identity signals across sessions.

```javascript
// ✓ CORRECT: Persistent context
const context = await chromium.launchPersistentContext('./profile-path', {
  headless: false
});
```

This is **not a workaround** — it's how real browsers behave.

### Why This Works

Cloudflare sees:
1. Same cookies (cf_clearance persists)
2. Same TLS fingerprint
3. Same browser entropy
4. Same localStorage/sessionStorage
5. **Continuous identity**

Result: Challenge issued **once**, then cached.

## Implementation

### Using AuthManager (Recommended)

```javascript
const { chromium } = require('playwright');
const { AuthManager } = require('./playwright-session-manager');

const authManager = new AuthManager();

// Configure user (persistent across runs)
authManager.addUser('alice', {
  email: 'alice@example.com',
  password: 'secret123'
});

// Launch persistent context
const context = await authManager.launchUserContext(chromium, 'alice');
const page = context.pages()[0] || await context.newPage();

// Use normally
await page.goto('https://gitlab.com/explore');
// Cloudflare challenge happens ONCE, then remembered forever

await context.close();
```

### Manual Approach

```javascript
const { chromium } = require('playwright');

const context = await chromium.launchPersistentContext(
  './browser-profiles/alice', // Profile saved here
  {
    headless: false,
    viewport: { width: 1280, height: 720 }
  }
);

const page = context.pages()[0] || await context.newPage();
await page.goto('https://cloudflare-protected-site.com');
```

## Demonstrations

### Show Correct Approach
```bash
cd scripts
npm run demo:persistent
```

Opens GitLab with persistent context. Complete Cloudflare once, then rerun — no loop.

### Show Wrong Approach (Educational)
```bash
npm run demo:persistent:wrong
```

Shows ephemeral context — Cloudflare loops every time.

### Compare Approaches
```bash
npm run demo:persistent:compare
```

Prints technical comparison table.

## When to Use Persistent Contexts

### ✓ Use For:
- **Any** Cloudflare-protected site
- GitLab (tooling)
- SaaS applications (targets)
- Long-running test suites
- Multi-user IDOR testing

### ✗ Don't Use For:
- Intentionally testing "fresh user" scenarios
- Testing cookie/cache isolation
- Benchmarking cold-start performance

## Architecture Implications

### Separation of Concerns

```
Tooling Traffic (GitLab, CI)
├── Use persistent contexts
├── No MITM proxy
└── Normal browser

Target Traffic (SaaS app under test)
├── Use persistent contexts (multi-user)
├── Optional MITM proxy (for analysis)
└── Headed Playwright
```

### Per-User Profiles

The AuthManager creates **one profile per user**:

```
scripts/auth-sessions/browser-profiles/
├── alice/          # Alice's persistent profile
├── bob/            # Bob's persistent profile
└── charlie/        # Charlie's persistent profile
```

This enables:
- Multi-user IDOR testing
- Independent session states
- Realistic user simulation

## Comparison to Other "Fixes"

| Fix | Stability | Correctness | Maintenance | Verdict |
|-----|-----------|-------------|-------------|---------|
| **Persistent contexts** | ★★★★★ | ✓ Correct | Low | **Use this** |
| Disable proxy temporarily | ★★★☆☆ | Partial | Medium | Mitigation only |
| Use "real browser" manually | ★★★★☆ | External | High | Doesn't scale |
| Stealth/fingerprint hardening | ★★☆☆☆ | ❌ Arms race | Very High | Breaks unpredictably |
| Change network/IP | ★★☆☆☆ | Partial | Low control | Insufficient alone |

Only persistent contexts are **architecturally sound**.

## Troubleshooting

### Still Getting Verification Loops?

1. **Verify profile persistence:**
   ```bash
   ls -la scripts/auth-sessions/browser-profiles/alice/
   ```
   Should contain cookies, localStorage, etc.

2. **Check if MITM proxy is active:**
   - Disable Burp/mitmproxy for GitLab
   - Proxy only target domains

3. **Verify cookies are saved:**
   Open profile → DevTools → Application → Cookies
   Should see `cf_clearance` cookie

4. **Check IP reputation:**
   - Residential IP > VPN > Hosting IP
   - Mobile hotspot often works well

### Profile Corruption?

Delete and recreate:
```bash
rm -rf scripts/auth-sessions/browser-profiles/alice
npm run demo:persistent  # Recreates profile
```

## Best Practices

### ✓ Do:
- Use persistent contexts for all Cloudflare-protected sites
- One profile per test user
- Commit `.gitkeep`, ignore actual profiles
- Document which sites require persistent contexts

### ✗ Don't:
- Mix ephemeral and persistent contexts for same site
- Commit browser profiles to git (large, contains session data)
- Use MITM proxy for tooling domains (GitLab, etc.)
- Try to "outsmart" Cloudflare with stealth plugins

## Summary

**Problem**: Cloudflare verification loops with ephemeral contexts

**Root Cause**: Client identity signals reset every session

**Solution**: Persistent browser contexts (`launchPersistentContext`)

**Why It Works**: Preserves cookies, TLS fingerprint, entropy — exactly like real browsers

**Result**: Challenge issued once, then cached indefinitely

This is not a workaround. This is the **correct** approach.

---

## References

- Playwright Persistent Contexts: https://playwright.dev/docs/api/class-browsertype#browser-type-launch-persistent-context
- Cloudflare Bot Management: https://developers.cloudflare.com/bots/
- TLS Fingerprinting: https://tlsfingerprint.io/
