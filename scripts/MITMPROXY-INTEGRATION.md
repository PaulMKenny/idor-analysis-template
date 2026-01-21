# mitmproxy Integration for UI Automation

Complete guide for using mitmproxy with Playwright to capture partitioned HTTP traffic for IDOR testing.

## Overview

This integration enables:
- **Partitioned capture**: User → Session → Action hierarchy
- **Real-time traffic recording**: HTTP captured during Playwright tests
- **Multi-user comparison**: Compare Alice vs Bob traffic for same actions
- **Clean separation**: Control signals (markers) vs actual traffic

## Architecture

```
Playwright Test
    ↓ (signals action via marker request)
mitmproxy (src/mitm_capture.py)
    ↓ (captures & partitions traffic)
ui-automation/recordings/
    ├── alice/
    │   └── session-1/
    │       ├── action1-timestamp.json
    │       └── action2-timestamp.json
    └── bob/
        └── session-1/
            └── action1-timestamp.json
```

## Installation

### 1. Install mitmproxy

```bash
# macOS
brew install mitmproxy

# Linux
pip install mitmproxy

# Or via official binaries
# https://mitmproxy.org/
```

### 2. Install Playwright (if not already installed)

```bash
cd scripts/
npm install
npx playwright install chromium
```

### 3. Install mitmproxy CA certificate in browser

```bash
# Start mitmproxy once
mitmdump

# Visit http://mitm.it in your browser
# Download and install the certificate for your OS/browser
```

## Quick Start

### Step 1: Start mitmproxy

```bash
# From project root
mitmdump -s src/mitm_capture.py --listen-port 8080
```

You should see:
```
[mitmproxy] Listening on 0.0.0.0:8080
```

### Step 2: Run Playwright test

```bash
# In another terminal
cd scripts/
npx playwright test playwright-mitm-example.js --headed
```

You'll see:
```
[mitmproxy] action start → alice/session-1/navigate_to_wikipedia
[mitmproxy] saved partition → alice/session-1/navigate_to_wikipedia-1737472100123.json
[mitmproxy] action start → alice/session-1/search_for_idor
...
```

### Step 3: Browse captured partitions

```bash
./scripts/idor_interface.py

> m    # Toggle to ui_automation mode
> m
> 3    # Browse tree

# Select partition files
# Save to UI AUTOMATION saved box with user context
```

## Usage Patterns

### Pattern 1: Simple Action Signaling

```javascript
const { ActionManager } = require('./playwright-mitm-integration');

test('basic test', async ({ page }) => {
  const actions = new ActionManager(page, 'alice', 'session-1');

  await actions.start('navigate to homepage');
  await page.goto('https://example.com');
  await page.waitForLoadState('networkidle');

  await actions.start('click about');
  await page.click('a:has-text("About")');
  await page.waitForLoadState('networkidle');
});
```

**Result:**
```
ui-automation/recordings/alice/session-1/
├── navigate_to_homepage-1737472100123.json
└── click_about-1737472105456.json
```

### Pattern 2: Multi-User Testing (IDOR Detection)

```javascript
test('multi-user idor test', async ({ page, browser }) => {
  // Alice's workflow
  const aliceActions = new ActionManager(page, 'alice', 'session-1');

  await aliceActions.start('access project');
  await page.goto('https://app.com/projects/123');
  await page.waitForLoadState('networkidle');

  // Bob's workflow (same actions)
  const bobContext = await browser.newContext(mitmproxyConfig);
  const bobPage = await bobContext.newPage();
  const bobActions = new ActionManager(bobPage, 'bob', 'session-1');

  await bobActions.start('access project');
  await bobPage.goto('https://app.com/projects/123');  // Same URL!
  await bobPage.waitForLoadState('networkidle');

  await bobContext.close();

  // Compare: Did Bob access Alice's project?
  // ui-automation/recordings/alice/session-1/access_project-*.json
  // ui-automation/recordings/bob/session-1/access_project-*.json
});
```

### Pattern 3: With Existing ActionAwareRequestLogger

```javascript
const {
  createSessionClock,
  createActionAwareRequestLogger
} = require('./playwright-session-manager');

test('with logger', async ({ page }) => {
  const now = createSessionClock();
  const logger = createActionAwareRequestLogger(page, now);

  // Pass logger to ActionManager for dual logging
  const actions = new ActionManager(page, 'alice', 'session-1', logger);

  await actions.start('open projects');  // Logs to both!
  await page.goto('https://app.com/projects');

  const capture = logger.stop();
  // You now have both Playwright logger data AND mitmproxy partitions
});
```

## Captured Partition Format

Each action creates a JSON file with this structure:

```json
{
  "meta": {
    "user": "alice",
    "session_id": "session-1",
    "action_name": "navigate to projects",
    "action_start_time": "2026-01-21T10:30:15.234Z",
    "action_end_time": "2026-01-21T10:30:16.891Z",
    "total_requests": 3,
    "capture_source": "mitmproxy"
  },
  "transactions": [
    {
      "seq": 1,
      "timestamp": "2026-01-21T10:30:15.456Z",
      "request": {
        "method": "GET",
        "url": "https://app.com/api/v1/projects",
        "path": "/api/v1/projects",
        "headers": {...},
        "body": null,
        "body_size": 0
      },
      "response": {
        "status": 200,
        "reason": "OK",
        "headers": {...},
        "body": "{\"projects\": [...]}",
        "body_size": 3456
      },
      "timing": {
        "request_start": "2026-01-21T10:30:15.456Z",
        "response_end": "2026-01-21T10:30:15.678Z",
        "duration_ms": 222
      }
    }
  ]
}
```

## Directory Structure

```
ui-automation/recordings/
├── alice/
│   ├── session-1/
│   │   ├── navigate_to_projects-1737472100123.json
│   │   ├── click_first_project-1737472105456.json
│   │   └── open_documents-1737472110789.json
│   └── session-2/
│       └── ...
└── bob/
    └── session-1/
        ├── navigate_to_projects-1737472150234.json
        └── click_first_project-1737472155567.json
```

**Naming convention:**
```
{action_name_sanitized}-{timestamp_milliseconds}.json
```

**Hierarchy:**
```
recordings/{user}/{session}/{action}-{timestamp}.json
```

## Integration with idor_interface.py

The captured partitions integrate seamlessly with the IDOR interface:

```bash
./scripts/idor_interface.py

> m    # Toggle to UI_AUTOMATION mode
> m

> 3    # Browse tree & save path
[Shows recordings/ hierarchy]
[Select partition file]
Which user owns this? alice

> s    # Show saved box
=== UI AUTOMATION SAVED BOX ===

----User alice:
  [1] recordings/alice/session-1/navigate_to_projects-*.json
  [2] recordings/alice/session-1/click_first_project-*.json

----User bob:
  [1] recordings/bob/session-1/navigate_to_projects-*.json

> c    # Open in Codium (compare alice vs bob)
```

## API Reference

### ActionManager

```javascript
new ActionManager(page, user, session, logger?)
```

**Parameters:**
- `page` - Playwright page object
- `user` - User identifier (e.g., 'alice', 'bob')
- `session` - Session identifier (e.g., 'session-1')
- `logger` - Optional ActionAwareRequestLogger instance

**Methods:**

#### `await actions.start(actionName)`
Signal new action to mitmproxy and optionally start Playwright logger.

#### `await actions.signal(actionName)`
Signal action without starting logger (lightweight).

### mitmproxyConfig

Pre-configured proxy settings for Playwright:

```javascript
const { mitmproxyConfig } = require('./playwright-mitm-integration');

test.use(mitmproxyConfig);
// Equivalent to:
test.use({
  proxy: { server: 'http://127.0.0.1:8080' },
  ignoreHTTPSErrors: true
});
```

### checkMitmproxy(page)

Verify mitmproxy is running:

```javascript
const isRunning = await checkMitmproxy(page);
if (!isRunning) {
  console.warn('mitmproxy not detected');
}
```

## Troubleshooting

### Problem: "mitmproxy not detected"

**Solution:**
```bash
# Check if mitmproxy is running
lsof -i :8080

# Start mitmproxy if not running
mitmdump -s src/mitm_capture.py --listen-port 8080
```

### Problem: SSL certificate errors

**Solution:**
1. Visit http://mitm.it in your browser
2. Download and install certificate for your OS
3. Restart browser
4. Or use `ignoreHTTPSErrors: true` (already in mitmproxyConfig)

### Problem: No partitions created

**Checklist:**
- ✅ mitmproxy running?
- ✅ Playwright test using `test.use(mitmproxyConfig)`?
- ✅ Calling `await actions.start()` before navigation?
- ✅ Check mitmproxy console for "action start" messages

### Problem: Browser shows "Failed to fetch" for marker

**This is normal** if you're not using the optional response handler. The marker request may fail visibly in console but still works. To fix:

The current implementation responds to markers, so this shouldn't happen. If it does, check mitmproxy logs.

### Problem: Actions not flushing to disk

**Solution:**
Actions are flushed when:
- Next action starts
- Test completes (mitmproxy `done()` hook)

Ensure your test doesn't exit immediately after last action.

## Advanced Usage

### Custom Proxy Port

```javascript
const actions = new ActionManager(page, 'alice', 'session-1');
actions.proxyUrl = 'http://127.0.0.1:9090';  // Custom port
```

### Action Naming Best Practices

**Good:**
```javascript
await actions.start('navigate to projects');
await actions.start('click first project');
await actions.start('open documents tab');
```

**Bad:**
```javascript
await actions.start('action1');  // Not descriptive
await actions.start('do stuff');  // Too vague
await actions.start('click/button/test');  // Contains slashes
```

**Rules:**
- Use descriptive names
- Avoid special characters (/, \, etc.)
- Use lowercase with spaces (auto-sanitized to underscores)
- Be consistent across users for comparison

### Multiple Sessions in One Test

```javascript
test('multiple sessions', async ({ page }) => {
  // Session 1
  const session1 = new ActionManager(page, 'alice', 'session-1');
  await session1.start('login');
  // ... actions ...

  // Session 2 (e.g., after logout/re-login)
  const session2 = new ActionManager(page, 'alice', 'session-2');
  await session2.start('login again');
  // ... actions ...

  // Both sessions saved separately:
  // alice/session-1/*.json
  // alice/session-2/*.json
});
```

## Next Steps

After capturing partitions:

1. **Browse in idor_interface.py**
   ```bash
   ./scripts/idor_interface.py
   > m (switch to ui_automation)
   > 3 (browse tree)
   ```

2. **Compare partitions manually**
   ```bash
   code --diff \
     ui-automation/recordings/alice/session-1/action-*.json \
     ui-automation/recordings/bob/session-1/action-*.json
   ```

3. **Run IDOR analyzer** (future feature)
   ```bash
   python3 src/idor_analyzer.py <partition.json>
   ```

4. **Export to Burp format** (future feature)
   ```bash
   python3 scripts/partition_to_burp.py <partition.json>
   ```

## See Also

- `src/mitm_capture.py` - mitmproxy addon implementation
- `scripts/playwright-mitm-integration.js` - Playwright helpers
- `scripts/playwright-mitm-example.js` - Complete examples
- `scripts/PLAYWRIGHT-README.md` - Playwright session manager docs
- `INTEGRATION-GUIDE.md` - Complete 3-mode workflow guide
