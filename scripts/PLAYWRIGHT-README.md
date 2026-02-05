# Playwright Session Manager

A user-agnostic session recording and replay system for multi-user testing workflows, particularly useful for IDOR (Insecure Direct Object Reference) vulnerability testing.

## Features

- **Saved Box**: Store entire action sequences as reusable workflows
- **User-Agnostic Sequences**: Record once, replay with any configured user
- **Multi-User Session Management**: Switch between user credentials seamlessly
- **Interactive CLI**: Menu-driven interface with tree browser
- **Codium Integration**: Edit sequences as JSON directly in VSCodium
- **Request Correlation**: Track all HTTP requests per action with timestamps
- **Recording Comparison**: Compare how different users experience the same workflow

## Quick Start

### Installation

```bash
cd scripts/
npm init -y  # if package.json doesn't exist
npm install --save-dev @playwright/test
npx playwright install chromium
```

### Interactive CLI Mode

```bash
node playwright-session-manager.js
```

This launches an interactive menu:

```
========================================
  PLAYWRIGHT SESSION MANAGER
========================================
1. Configure Users
2. View Saved Sequences (Tree)
3. Record New Sequence
4. Replay Sequence
5. Edit Sequence (Codium)
6. Delete Sequence
7. Compare Recordings
8. Exit
========================================
```

### Programmatic Mode

```bash
# Run examples
npx playwright test playwright-examples.js --headed

# Record new sequence
npx playwright test --grep "record-mode" --headed

# Replay sequence
npx playwright test --grep "replay-mode" --headed
```

## Core Concepts

### 1. Saved Sequences (The Saved Box)

A **sequence** is a series of user actions stored in a user-agnostic format:

```json
{
  "id": "seq-1737340123456",
  "name": "Project Document Access",
  "description": "Navigate to projects and view first document",
  "created": "2026-01-19T10:30:00.000Z",
  "actions": [
    {
      "step": "navigate to projects",
      "t_start_sec": "2.345",
      "requests": [
        {
          "method": "GET",
          "url": "https://app.com/api/v1/projects",
          "status": 200
        }
      ]
    },
    {
      "step": "click first project",
      "t_start_sec": "5.678",
      "requests": [
        {
          "method": "GET",
          "url": "https://app.com/api/v1/projects/123456",
          "status": 200
        }
      ]
    }
  ]
}
```

Key characteristics:
- **User-agnostic**: No credentials stored in sequence
- **Replayable**: Same sequence works with alice, bob, or any configured user
- **Timestamped**: All actions correlated to video timestamps
- **Request-tracked**: Full HTTP request/response data per action

### 2. User Sessions

User credentials and session state are managed separately:

```javascript
authManager.addUser('alice', {
  email: 'alice@company.com',
  password: 'secret123'
});

// Login saves cookies, localStorage, sessionStorage
await authManager.login(page, 'alice', loginFunction);

// Later: load saved session (no re-login needed)
await authManager.loadSession(page, 'alice');
```

### 3. Recordings

A **recording** is a sequence executed by a specific user:

```
./saved-sequences/recordings/
├── seq-123-alice-1737340123456.json  # Alice's execution
├── seq-123-bob-1737340987654.json    # Bob's execution (same sequence)
└── seq-456-alice-1737341000000.json
```

Recordings preserve:
- Full request/response bodies
- HTTP headers
- Response status codes
- Timing data

## Workflows

### Basic Recording Workflow

```javascript
const now = createSessionClock();
const logger = createActionAwareRequestLogger(page, now);
const sequenceManager = new SequenceManager();

// Perform actions
logger.startAction('navigate to dashboard');
await page.goto('https://app.com/dashboard');

logger.startAction('click settings');
await page.getByRole('link', { name: 'Settings' }).click();

// Save sequence
const capture = logger.stop();
const sequence = sequenceManager.createFromCapture(capture, {
  name: 'Dashboard to Settings',
  description: 'Navigate from dashboard to settings page'
});
```

### Multi-User Replay Workflow

```javascript
const authManager = new AuthManager();
const sequenceManager = new SequenceManager();

// Configure users
authManager.addUser('alice', { email: 'alice@app.com', password: 'pass1' });
authManager.addUser('bob', { email: 'bob@app.com', password: 'pass2' });

// Record as Alice
const aliceLogger = createActionAwareRequestLogger(page, now);
await authManager.login(page, 'alice', loginFn);
// ... perform actions ...
const aliceCapture = aliceLogger.stop();
const sequence = sequenceManager.createFromCapture(aliceCapture, {...});

// Replay as Bob (different context)
const bobContext = await browser.newContext();
const bobPage = await bobContext.newPage();
await authManager.loadSession(bobPage, 'bob');

await sequenceManager.replay(bobPage, sequence.id, async (page, actions) => {
  for (const action of actions) {
    // Execute action in Bob's context
    // Same URLs, same clicks, but with Bob's session
  }
});
```

## IDOR Testing Pattern

The primary use case is testing for authorization vulnerabilities:

### Step 1: Capture Legitimate Access (Alice)

```javascript
// Alice logs in and accesses her project
logger.startAction('alice: access project');
await page.goto('https://app.com/api/v1/projects/123456/documents');

// Save sequence
const sequence = sequenceManager.createFromCapture(capture, {
  name: 'Project Document Access',
  testType: 'idor-candidate'
});
```

### Step 2: Replay with Different User (Bob)

```javascript
// Bob attempts to access Alice's project (same URL)
await authManager.loadSession(bobPage, 'bob');
await sequenceManager.replay(bobPage, sequence.id, replayFn);
```

### Step 3: Compare Results

```javascript
const recordings = sequenceManager.getRecordings(sequence.id);

// Check response codes:
// - Both 200 OK = IDOR vulnerability (Bob accessed Alice's data)
// - Alice 200, Bob 403 = Proper authorization
// - Alice 200, Bob 404 = Proper authorization (resource hidden)
```

## CLI Usage Examples

### Configure Users

```
Select option: 1

User ID (e.g., alice): alice
Email: alice@acme-corp.com
Password: ********
✓ User alice configured
```

### View Sequences (Tree)

```
Select option: 2

=== SAVED SEQUENCES (Tree View) ===

├── [seq-1737340123456] Project Access
│   │   Description: Navigate to projects and open documents
│   │   Created: 2026-01-19T10:30:00.000Z
│   │   Actions: 5
│   ├── 1. navigate to projects
│   ├── 2. click first project
│   └── 3. open documents tab
│   └── ... (2 more actions)

└── [seq-1737340987654] Settings Update
    │   Description: Update user settings
    │   Created: 2026-01-19T11:45:00.000Z
    │   Actions: 3
    ├── 1. navigate to settings
    ├── 2. click profile tab
    └── 3. update email
```

### Record New Sequence

```
Select option: 3

Sequence name: API Access Pattern
Description: Access user API endpoint
Record as user: alice

✓ Config saved. Run: npx playwright test --grep "record-mode"
```

Then in another terminal:

```bash
npx playwright test --grep "record-mode" --headed
# Use Playwright Inspector to step through actions
# Press "Resume" button for each action
```

### Replay Sequence

```
Select option: 4

Sequence ID to replay: seq-1737340123456
Replay as user: bob

✓ Config saved. Run: npx playwright test --grep "replay-mode"
```

### Edit Sequence (Codium)

```
Select option: 5

Sequence ID to edit: seq-1737340123456

✓ Opening seq-1737340123456.edit.json in VSCodium...
```

VSCodium opens with the sequence JSON. Edit and save:

```json
{
  "id": "seq-1737340123456",
  "name": "Project Access (Updated)",
  "description": "Updated description",
  "actions": [
    // Modify actions, add new ones, etc.
  ]
}
```

### Compare Recordings

```
Select option: 7

Sequence ID: seq-1737340123456

Recordings:
1. User: alice, Time: 2026-01-19T10:30:00.000Z, Actions: 5
2. User: bob, Time: 2026-01-19T11:00:00.000Z, Actions: 5

✓ Use external diff tool to compare files
   Location: ./saved-sequences/recordings/
```

Then compare:

```bash
# Visual diff
code --diff \
  ./saved-sequences/recordings/seq-123-alice-*.json \
  ./saved-sequences/recordings/seq-123-bob-*.json

# Terminal diff
diff -u \
  <(jq '.buckets[].requests[].status' ./saved-sequences/recordings/seq-123-alice-*.json) \
  <(jq '.buckets[].requests[].status' ./saved-sequences/recordings/seq-123-bob-*.json)
```

## Directory Structure

```
./auth-sessions/
├── alice-session.json      # Cookies, localStorage, sessionStorage
├── alice-capture.json      # Last capture for alice
├── alice-ids.json          # Extracted IDs (if using ID extraction)
├── bob-session.json
└── bob-capture.json

./saved-sequences/
├── sequences.json          # All sequence definitions
└── recordings/
    ├── seq-123-alice-1737340123456.json
    ├── seq-123-bob-1737340987654.json
    └── seq-456-alice-1737341000000.json
```

## API Reference

### SequenceManager

```javascript
const sequenceManager = new SequenceManager('./saved-sequences');

// List all sequences
const sequences = sequenceManager.list();

// Get specific sequence
const seq = sequenceManager.get('seq-123');

// Create from capture
const sequence = sequenceManager.createFromCapture(buckets, {
  name: 'My Sequence',
  description: 'Description here'
});

// Update sequence
sequenceManager.update('seq-123', { name: 'New Name' });

// Delete sequence
sequenceManager.delete('seq-123');

// Display tree view
sequenceManager.displayTree();

// Replay sequence
await sequenceManager.replay(page, 'seq-123', async (page, actions) => {
  // Custom replay logic
});

// Save recording
sequenceManager.saveRecording('seq-123', capture, 'alice');

// Get recordings for sequence
const recordings = sequenceManager.getRecordings('seq-123');
```

### AuthManager

```javascript
const authManager = new AuthManager('./auth-sessions');

// Add user
authManager.addUser('alice', {
  email: 'alice@app.com',
  password: 'secret'
});

// Login (saves session)
await authManager.login(page, 'alice', async (page, user) => {
  await page.goto('https://app.com/login');
  await page.fill('[name=email]', user.email);
  await page.fill('[name=password]', user.password);
  await page.click('button[type=submit]');
});

// Load saved session
await authManager.loadSession(page, 'alice');

// Get all user IDs
const users = authManager.getUserIds();

// Save capture
authManager.saveCapture(buckets, 'alice');
```

### ActionLogger

```javascript
const now = createSessionClock();
const logger = createActionAwareRequestLogger(page, now);

// Start action (correlates subsequent requests)
logger.startAction('click submit button');
await page.click('button[type=submit]');

// Stop logging and get all buckets
const capture = logger.stop();
// capture = [{ action, t_start_sec, requests: [...] }, ...]
```

## Integration with IDOR Analyzer

While this Playwright tool is separate from the IDOR analysis Python scripts, they can work together:

### Workflow 1: Playwright → Burp → IDOR Analyzer

```javascript
// Configure Playwright to use Burp proxy
test.use({
  proxy: { server: 'http://127.0.0.1:8080' },
  ignoreHTTPSErrors: true
});

// Run sequences through Burp
// Export Burp history as XML
// Run: python3 src/idor_analyzer.py history.xml
```

### Workflow 2: Direct Comparison (No Burp)

```javascript
// Compare recordings directly
const aliceRecording = require('./saved-sequences/recordings/seq-123-alice-*.json');
const bobRecording = require('./saved-sequences/recordings/seq-123-bob-*.json');

// Check for IDOR
aliceRecording.buckets.forEach((aliceBucket, idx) => {
  const bobBucket = bobRecording.buckets[idx];

  aliceBucket.requests.forEach((aliceReq, reqIdx) => {
    const bobReq = bobBucket.requests[reqIdx];

    if (aliceReq.status === 200 && bobReq.status === 200) {
      console.log(`⚠️  POTENTIAL IDOR: ${aliceReq.url}`);
      console.log(`   Both users got 200 OK`);
    } else if (aliceReq.status === 200 && bobReq.status === 403) {
      console.log(`✓ Proper authorization: ${aliceReq.url}`);
    }
  });
});
```

## Tips & Best Practices

### 1. Keep Sequences Focused
- One sequence = one user journey
- Break complex workflows into multiple sequences
- Easier to debug and replay

### 2. Use Descriptive Names
```javascript
// Good
name: "Project Document Access - Admin Role"
description: "Navigate to projects, select first project, view documents tab"

// Bad
name: "test1"
description: ""
```

### 3. Session Management
- Re-login periodically (sessions expire)
- Save sessions after successful login
- Use `loadSession()` for faster test iteration

### 4. IDOR Testing
- Always test with at least 2 users
- Compare response codes AND response bodies
- Document findings in sequence metadata

### 5. Video Correlation
- Enable video: `test.use({ video: 'on' })`
- Timestamps in sequences match video playback time
- Use video to understand what each action does

## Troubleshooting

### "No saved session" error
```javascript
// Solution: Login first
await authManager.login(page, 'alice', loginFn);

// Then subsequent tests can use:
await authManager.loadSession(page, 'alice');
```

### "Sequence not found" error
```javascript
// List all sequences to verify ID
sequenceManager.displayTree();

// Or check sequences.json directly
const sequences = sequenceManager.list();
console.log(sequences.map(s => s.id));
```

### Replay doesn't work
- Sequences don't store exact selectors
- You must implement replay logic based on action names
- Use action.requests to get original URLs if needed

Example:
```javascript
await sequenceManager.replay(page, seqId, async (page, actions) => {
  for (const action of actions) {
    if (action.step === 'navigate to projects') {
      await page.click('a[href="/projects"]');
    } else if (action.step === 'click first project') {
      await page.click('.project-item:first-child');
    }
    // etc.
  }
});
```

## Advanced Usage

### Custom Replay Strategies

```javascript
// Strategy 1: URL-based replay (API testing)
await sequenceManager.replay(page, seqId, async (page, actions) => {
  for (const action of actions) {
    if (action.requests.length > 0) {
      const url = action.requests[0].url;
      await page.goto(url);
    }
  }
});

// Strategy 2: Smart selector mapping
const selectorMap = {
  'navigate to projects': 'a[href="/projects"]',
  'click first project': '.project-list > li:first-child',
  'open documents': 'button[data-tab="documents"]'
};

await sequenceManager.replay(page, seqId, async (page, actions) => {
  for (const action of actions) {
    const selector = selectorMap[action.step];
    if (selector) {
      await page.click(selector);
    }
  }
});
```

### Conditional Actions

```javascript
// Add conditions to sequences
sequenceManager.update(seqId, {
  actions: [
    {
      step: 'navigate to projects',
      condition: { role: 'admin' }  // Only for admin users
    },
    {
      step: 'view all users',
      condition: { role: 'admin' }
    }
  ]
});

// Replay with conditions
await sequenceManager.replay(page, seqId, async (page, actions) => {
  const userRole = 'user'; // or 'admin'

  for (const action of actions) {
    if (action.condition && action.condition.role !== userRole) {
      console.log(`Skipping: ${action.step} (requires ${action.condition.role})`);
      continue;
    }
    // Execute action...
  }
});
```

## License

(Same as parent IDOR analysis repository)
