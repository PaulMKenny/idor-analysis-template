# mitmproxy Integration - Quick Start

Get started with mitmproxy + Playwright traffic capture in 5 minutes.

## What This Does

Captures HTTP traffic during Playwright tests, partitioned by:
```
User (alice/bob) → Session (session-1) → Action (navigate, click, etc.)
```

Each action's traffic is saved as a separate JSON file for analysis and comparison.

## Installation (One Time)

### 1. Install mitmproxy

```bash
# macOS
brew install mitmproxy

# Linux
pip install mitmproxy

# Verify
mitmdump --version
```

### 2. Install certificate

```bash
# Start mitmproxy once
mitmdump

# In browser, visit: http://mitm.it
# Download certificate for your OS
# Install it
# Restart browser
```

## Usage (Two Terminals)

### Terminal 1: Start mitmproxy

```bash
cd /path/to/idor-analysis-template

# Option A: Using helper script
./scripts/start-mitm.sh

# Option B: Direct command
mitmdump -s src/mitm_capture.py --listen-port 8080
```

You should see:
```
[mitmproxy] Listening on 0.0.0.0:8080
```

### Terminal 2: Run Playwright test

```bash
cd scripts/

# Run example (Alice + Bob workflows)
npm run test:mitm

# Or specific user
npm run test:mitm:alice
npm run test:mitm:bob
```

Watch Terminal 1 for capture output:
```
[mitmproxy] action start → alice/session-1/navigate_to_wikipedia
[mitmproxy] saved partition → alice/session-1/navigate_to_wikipedia-1737472100123.json
```

## View Captured Traffic

### Option 1: Use idor_interface.py

```bash
./scripts/idor_interface.py

> m    # Toggle to ui_automation mode
> m
> 3    # Browse tree

# Tree view:
ui-automation/recordings/
├── alice/
│   └── session-1/
│       ├── navigate_to_wikipedia-1737472100123.json
│       └── search_for_idor-1737472105456.json
└── bob/
    └── session-1/
        └── navigate_to_wikipedia-1737472150234.json

[Select files, assign to users in saved box]
```

### Option 2: Direct filesystem

```bash
ls -la ui-automation/recordings/alice/session-1/

# View JSON
cat ui-automation/recordings/alice/session-1/navigate_to_wikipedia-*.json | jq .
```

### Option 3: Open in editor

```bash
code ui-automation/recordings/
```

## Example Partition File

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
        "headers": {...},
        "body": null
      },
      "response": {
        "status": 200,
        "headers": {...},
        "body": "{\"projects\": [...]}"
      },
      "timing": {
        "duration_ms": 222
      }
    }
  ]
}
```

## Create Your Own Test

```javascript
// your-test.spec.js
const { test } = require('@playwright/test');
const {
  ActionManager,
  mitmproxyConfig
} = require('./playwright-mitm-integration');

test.use(mitmproxyConfig);

test('my test', async ({ page }) => {
  const actions = new ActionManager(page, 'alice', 'session-1');

  await actions.start('navigate to homepage');
  await page.goto('https://your-app.com');
  await page.waitForLoadState('networkidle');

  await actions.start('click login');
  await page.click('a[href="/login"]');
  await page.waitForLoadState('networkidle');

  // Each action's traffic saved separately!
});
```

Run it:
```bash
npx playwright test your-test.spec.js --headed
```

## IDOR Testing Pattern

```javascript
test('idor test', async ({ page, browser }) => {
  // Alice accesses resource
  const alice = new ActionManager(page, 'alice', 'session-1');
  await alice.start('access project 123');
  await page.goto('https://app.com/projects/123');

  // Bob tries to access Alice's resource
  const bobContext = await browser.newContext(mitmproxyConfig);
  const bobPage = await bobContext.newPage();
  const bob = new ActionManager(bobPage, 'bob', 'session-1');

  await bob.start('access project 123');
  await bobPage.goto('https://app.com/projects/123');  // Same URL!

  await bobContext.close();

  // Compare partitions:
  // alice/session-1/access_project_123-*.json
  // bob/session-1/access_project_123-*.json
  //
  // Both 200 OK? → IDOR vulnerability
  // Alice 200, Bob 403? → Proper authorization
});
```

## Troubleshooting

### "Connection refused" or "ECONNREFUSED"

**Problem:** mitmproxy not running

**Solution:**
```bash
# Terminal 1
./scripts/start-mitm.sh
```

### "Certificate error" or "SSL error"

**Problem:** mitmproxy certificate not installed

**Solution:**
1. Start: `mitmdump`
2. Visit: http://mitm.it
3. Download + install certificate
4. Restart browser

### "No partitions created"

**Checklist:**
- ✅ mitmproxy running? (check Terminal 1)
- ✅ Test uses `test.use(mitmproxyConfig)`?
- ✅ Calling `await actions.start()` before navigation?

### Still having issues?

Check the full documentation:
- `scripts/MITMPROXY-INTEGRATION.md` - Complete guide
- `scripts/playwright-mitm-example.js` - Working examples

## Next Steps

1. **Run example tests**
   ```bash
   npm run test:mitm
   ```

2. **Browse captured partitions**
   ```bash
   ./scripts/idor_interface.py
   ```

3. **Create your own tests**
   - Copy `playwright-mitm-example.js`
   - Replace URLs with your app
   - Add your login flow
   - Test multi-user access

4. **Compare alice vs bob**
   ```bash
   diff -u \
     ui-automation/recordings/alice/session-1/action-*.json \
     ui-automation/recordings/bob/session-1/action-*.json
   ```

5. **Run IDOR analyzer** (future feature)
   ```bash
   python3 src/idor_analyzer.py <partition.json>
   ```

## File Locations

```
src/mitm_capture.py                    # mitmproxy addon
scripts/playwright-mitm-integration.js # Playwright helpers
scripts/playwright-mitm-example.js     # Example tests
scripts/start-mitm.sh                  # Quick start script
ui-automation/recordings/              # Captured partitions
```

## See Also

- `scripts/MITMPROXY-INTEGRATION.md` - Full documentation
- `INTEGRATION-GUIDE.md` - Complete 3-mode workflow
- `scripts/PLAYWRIGHT-README.md` - Playwright session manager
