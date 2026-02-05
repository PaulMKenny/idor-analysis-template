# Quick Start Guide - Playwright Session Manager

Get started with user-agnostic session recording in 5 minutes.

## Setup (One Time)

```bash
cd scripts/

# Install dependencies
npm install

# Install Playwright browsers
npx playwright install chromium
```

## Option 1: Interactive CLI (Recommended for Beginners)

### Step 1: Launch CLI

```bash
npm run cli
```

### Step 2: Configure Users

```
Select option: 1

User ID: alice
Email: alice@example.com
Password: pass123
✓ User alice configured

User ID: bob
Email: bob@example.com
Password: pass456
✓ User bob configured
```

### Step 3: Record a Sequence

In the CLI:
```
Select option: 3
Sequence name: Wikipedia Search
Description: Search Wikipedia for a topic
Record as user: alice
```

In another terminal:
```bash
npm run test:record
```

The browser will open with Playwright Inspector:
1. Click "Resume" to execute each action
2. Browser navigates to Wikipedia
3. Browser fills in search
4. Browser clicks search button
5. Sequence is saved automatically

### Step 4: View Your Saved Sequence

Back in the CLI:
```
Select option: 2
```

You'll see:
```
=== SAVED SEQUENCES (Tree View) ===

└── [seq-1737340123456] Wikipedia Search
    │   Description: Search Wikipedia for a topic
    │   Created: 2026-01-19T10:30:00.000Z
    │   Actions: 3
    ├── 1. goto wikipedia
    ├── 2. fill search
    └── 3. click search
```

### Step 5: Replay with Different User

In the CLI:
```
Select option: 4
Sequence ID: seq-1737340123456
Replay as user: bob
```

In another terminal:
```bash
npm run test:replay
```

The same sequence runs, but in Bob's context!

## Option 2: Programmatic (For Developers)

### Simple Recording

```javascript
// Save as: my-test.spec.js
const { test } = require('@playwright/test');
const {
  createSessionClock,
  createActionAwareRequestLogger,
  SequenceManager
} = require('./playwright-session-manager');

test('record my workflow', async ({ page }) => {
  const now = createSessionClock();
  const logger = createActionAwareRequestLogger(page, now);
  const sequenceManager = new SequenceManager();

  // Your actions here
  logger.startAction('navigate to homepage');
  await page.goto('https://example.com');

  logger.startAction('click login button');
  await page.click('a[href="/login"]');

  logger.startAction('fill credentials');
  await page.fill('#email', 'user@example.com');
  await page.fill('#password', 'password');

  logger.startAction('submit login form');
  await page.click('button[type="submit"]');

  // Save sequence
  const capture = logger.stop();
  const sequence = sequenceManager.createFromCapture(capture, {
    name: 'Login Flow',
    description: 'Complete login process'
  });

  console.log(`✓ Saved: ${sequence.id}`);
});
```

Run it:
```bash
npx playwright test my-test.spec.js --headed
```

### Multi-User Replay

```javascript
// Save as: idor-test.spec.js
const { test } = require('@playwright/test');
const {
  createSessionClock,
  createActionAwareRequestLogger,
  AuthManager,
  SequenceManager
} = require('./playwright-session-manager');

test('idor test', async ({ page, browser }) => {
  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();

  // Configure users
  authManager.addUser('alice', {
    email: 'alice@app.com',
    password: 'pass1'
  });
  authManager.addUser('bob', {
    email: 'bob@app.com',
    password: 'pass2'
  });

  // Record Alice accessing a resource
  const aliceLogger = createActionAwareRequestLogger(page, now);

  aliceLogger.startAction('alice: access protected resource');
  await page.goto('https://app.com/api/projects/123456');
  await page.waitForLoadState('networkidle');

  const aliceCapture = aliceLogger.stop();
  const sequence = sequenceManager.createFromCapture(aliceCapture, {
    name: 'Resource Access',
    description: 'Access project resource'
  });

  authManager.saveCapture(aliceCapture, 'alice');
  sequenceManager.saveRecording(sequence.id, aliceCapture, 'alice');

  console.log(`Alice: ${aliceCapture[0].requests[0].status}`); // Should be 200

  // Try same access as Bob
  const bobContext = await browser.newContext();
  const bobPage = await bobContext.newPage();
  const bobLogger = createActionAwareRequestLogger(bobPage, now);

  bobLogger.startAction('bob: access same resource');
  await bobPage.goto('https://app.com/api/projects/123456');
  await bobPage.waitForLoadState('networkidle');

  const bobCapture = bobLogger.stop();
  authManager.saveCapture(bobCapture, 'bob');
  sequenceManager.saveRecording(sequence.id, bobCapture, 'bob');

  console.log(`Bob: ${bobCapture[0].requests[0].status}`); // 200 = IDOR!, 403 = Good

  await bobContext.close();

  // Compare
  if (bobCapture[0].requests[0].status === 200) {
    console.log('🚨 IDOR DETECTED! Bob accessed Alice\'s resource');
  } else {
    console.log('✓ Proper authorization');
  }
});
```

Run it:
```bash
npx playwright test idor-test.spec.js --headed
```

## Option 3: Run Examples

We've included complete examples:

```bash
# Run all examples
npm run test:examples

# Or run specific ones:
npx playwright test playwright-examples.js --grep "example-1"  # Basic recording
npx playwright test playwright-examples.js --grep "example-2"  # Multi-user replay
npx playwright test playwright-examples.js --grep "example-4"  # IDOR testing
```

## Common Workflows

### Workflow 1: Record → Replay

```bash
# Terminal 1: Start CLI
npm run cli

# Configure users (option 1)
# Record sequence (option 3)

# Terminal 2: Run recording
npm run test:record

# Back to Terminal 1: Replay (option 4)

# Terminal 2: Run replay
npm run test:replay
```

### Workflow 2: Direct Testing (No CLI)

Create `my-workflow.spec.js`, then:

```bash
npx playwright test my-workflow.spec.js --headed
```

### Workflow 3: IDOR Testing

1. **Record legitimate access**
   ```javascript
   // As alice: access /api/projects/123
   // Save sequence
   ```

2. **Replay with different user**
   ```javascript
   // As bob: access same /api/projects/123
   // Compare responses
   ```

3. **Check results**
   ```bash
   # Compare recordings
   diff -u \
     auth-sessions/alice-capture.json \
     auth-sessions/bob-capture.json
   ```

## File Locations

After running, you'll have:

```
scripts/
├── auth-sessions/           # Created automatically
│   ├── alice-session.json   # Alice's session (cookies, etc.)
│   ├── alice-capture.json   # Alice's last capture
│   ├── bob-session.json
│   └── bob-capture.json
│
├── saved-sequences/         # Created automatically
│   ├── sequences.json       # All sequence definitions
│   └── recordings/
│       ├── seq-123-alice-*.json
│       └── seq-123-bob-*.json
│
└── test-results/            # Playwright default
```

## Pro Tips

### 1. Inspect Recordings

```bash
# Pretty print a recording
cat saved-sequences/recordings/seq-*-alice-*.json | jq .

# Extract just response codes
cat saved-sequences/recordings/seq-*-alice-*.json | jq '.buckets[].requests[].status'

# Compare alice vs bob response codes
diff -y \
  <(cat saved-sequences/recordings/seq-*-alice-*.json | jq '.buckets[].requests[].status') \
  <(cat saved-sequences/recordings/seq-*-bob-*.json | jq '.buckets[].requests[].status')
```

### 2. Edit Sequences

```bash
# Option A: Use CLI (opens VSCodium)
npm run cli
# Select option 5

# Option B: Edit directly
code saved-sequences/sequences.json
```

### 3. Share Sequences (Not Sessions!)

```bash
# Safe to commit (no credentials)
git add saved-sequences/sequences.json

# Never commit (contains cookies, passwords)
# (already in .gitignore)
git add auth-sessions/  # ❌ Don't do this!
```

### 4. Reset Everything

```bash
# Delete all saved data
rm -rf auth-sessions/ saved-sequences/

# Start fresh
npm run cli
```

## Next Steps

- Read [PLAYWRIGHT-README.md](./PLAYWRIGHT-README.md) for full documentation
- Check [playwright-examples.js](./playwright-examples.js) for more patterns
- Customize replay logic for your specific app
- Integrate with CI/CD for automated IDOR testing

## Troubleshooting

**Q: "User not configured" error**
```
A: Run `npm run cli` and add users via option 1
```

**Q: "Sequence not found" error**
```
A: Run `npm run cli` and check option 2 to see available sequences
   Use the exact sequence ID shown in brackets [seq-123...]
```

**Q: Recording doesn't show my actions**
```
A: Make sure to call `logger.startAction('action name')` before each user action
   The logger tracks requests that happen after startAction is called
```

**Q: Replay doesn't work**
```
A: Sequences store action names and URLs, not exact selectors
   You need to implement replay logic that maps action names to your app's UI
   See PLAYWRIGHT-README.md "Custom Replay Strategies" section
```

**Q: How do I test my own app?**
```
A: Modify the example tests:
   1. Change URLs to your app's URLs
   2. Update selectors to match your app's HTML
   3. Implement your app's login flow
   4. Record your app's specific workflows
```

## Getting Help

- **Full docs**: See [PLAYWRIGHT-README.md](./PLAYWRIGHT-README.md)
- **Examples**: See [playwright-examples.js](./playwright-examples.js)
- **IDOR workflow**: See parent repo's [docs/workflow.md](../docs/workflow.md)
