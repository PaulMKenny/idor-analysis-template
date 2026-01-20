const { test } = require('@playwright/test');
const {
  createSessionClock,
  createActionAwareRequestLogger,
  AuthManager,
  SequenceManager
} = require('./playwright-session-manager');

/* ---------- EXAMPLE 1: Simple Sequence Recording ---------- */
test('example-1: record wikipedia sequence', async ({ page }) => {
  const now = createSessionClock();
  const sequenceManager = new SequenceManager();
  const logger = createActionAwareRequestLogger(page, now);

  // Record actions
  logger.startAction('navigate to wikipedia');
  await page.goto('https://www.wikipedia.org/');

  logger.startAction('search for topic');
  await page.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('web security');

  logger.startAction('submit search');
  await page.getByRole('button', { name: 'Search' }).click();
  await page.waitForURL('**/wiki/**');

  logger.startAction('click first link');
  await page.getByRole('link').first().click();

  // Save sequence
  const capture = logger.stop();
  const sequence = sequenceManager.createFromCapture(capture, {
    name: 'Wikipedia Research Flow',
    description: 'Search Wikipedia and follow first result'
  });

  console.log(`\n✓ Saved sequence: ${sequence.id}`);
  sequenceManager.displayTree();
});

/* ---------- EXAMPLE 2: Multi-User Replay ---------- */
test('example-2: multi-user replay', async ({ page, browser }) => {
  const now = createSessionClock();
  const sequenceManager = new SequenceManager();

  // Get existing sequence (assumes example-1 ran first)
  const sequences = sequenceManager.list();
  if (sequences.length === 0) {
    console.log('❌ No sequences found. Run example-1 first.');
    return;
  }

  const sequence = sequences[0];
  console.log(`\n=== REPLAYING: ${sequence.name} ===`);

  // Replay as "user A"
  console.log('\n--- Context A (simulating user alice) ---');
  const loggerA = createActionAwareRequestLogger(page, now);

  await sequenceManager.replay(page, sequence.id, async (page, actions) => {
    for (const action of actions) {
      loggerA.startAction(`[USER-A] ${action.step}`);

      if (action.step.includes('navigate')) {
        await page.goto('https://www.wikipedia.org/');
      } else if (action.step.includes('search')) {
        await page.getByRole('searchbox').fill('javascript');
      } else if (action.step.includes('submit')) {
        await page.getByRole('button', { name: 'Search' }).click();
        await page.waitForURL('**/wiki/**');
      } else if (action.step.includes('click first')) {
        await page.getByRole('link').first().click();
      }
    }
  });

  const captureA = loggerA.stop();
  sequenceManager.saveRecording(sequence.id, captureA, 'user-a');

  // Replay as "user B" in new context
  console.log('\n--- Context B (simulating user bob) ---');
  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  const loggerB = createActionAwareRequestLogger(pageB, now);

  await sequenceManager.replay(pageB, sequence.id, async (page, actions) => {
    for (const action of actions) {
      loggerB.startAction(`[USER-B] ${action.step}`);

      if (action.step.includes('navigate')) {
        await page.goto('https://www.wikipedia.org/');
      } else if (action.step.includes('search')) {
        await page.getByRole('searchbox').fill('python');
      } else if (action.step.includes('submit')) {
        await page.getByRole('button', { name: 'Search' }).click();
        await page.waitForURL('**/wiki/**');
      } else if (action.step.includes('click first')) {
        await page.getByRole('link').first().click();
      }
    }
  });

  const captureB = loggerB.stop();
  sequenceManager.saveRecording(sequence.id, captureB, 'user-b');

  await contextB.close();

  // Compare results
  console.log('\n=== RECORDINGS COMPARISON ===');
  const recordings = sequenceManager.getRecordings(sequence.id);
  recordings.forEach(rec => {
    console.log(`  ${rec.user}: ${rec.actions} actions @ ${rec.timestamp}`);
  });
});

/* ---------- EXAMPLE 3: SaaS App Login + Actions ---------- */
test('example-3: saas app workflow', async ({ page }) => {
  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();
  const logger = createActionAwareRequestLogger(page, now);

  // Configure user (normally done via CLI)
  authManager.addUser('testuser', {
    email: 'test@example.com',
    password: 'testpass123'
  });

  // Login sequence
  logger.startAction('navigate to login page');
  await page.goto('https://example.com/login');

  logger.startAction('fill email');
  await page.getByLabel('Email').fill('test@example.com');

  logger.startAction('fill password');
  await page.getByLabel('Password').fill('testpass123');

  logger.startAction('click sign in');
  await page.getByRole('button', { name: 'Sign In' }).click();

  // Wait for dashboard or handle redirect
  // await page.waitForURL('**/dashboard');

  logger.startAction('navigate to projects');
  // await page.getByRole('link', { name: 'Projects' }).click();

  logger.startAction('click first project');
  // await page.getByRole('listitem').first().click();

  const capture = logger.stop();

  // Create sequence
  const sequence = sequenceManager.createFromCapture(capture, {
    name: 'SaaS App - Project Access',
    description: 'Login and access first project',
    category: 'authentication-workflow'
  });

  // Save session and recording
  authManager.saveCapture(capture, 'testuser');
  sequenceManager.saveRecording(sequence.id, capture, 'testuser');

  console.log(`\n✓ Workflow recorded: ${sequence.id}`);
  console.log('✓ This sequence can now be replayed with different users');
});

/* ---------- EXAMPLE 4: IDOR Testing Pattern ---------- */
test('example-4: idor testing workflow', async ({ page, browser }) => {
  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();

  // Configure two users
  authManager.addUser('alice', { email: 'alice@app.com', password: 'pass1' });
  authManager.addUser('bob', { email: 'bob@app.com', password: 'pass2' });

  // === PHASE 1: Capture Alice's legitimate access ===
  console.log('\n=== PHASE 1: CAPTURING ALICE SESSION ===');
  const aliceLogger = createActionAwareRequestLogger(page, now);

  // Simulate login and actions
  aliceLogger.startAction('alice: login');
  await page.goto('https://www.wikipedia.org/'); // Replace with your app

  aliceLogger.startAction('alice: access resource');
  await page.goto('https://www.wikipedia.org/wiki/Computer_security');

  aliceLogger.startAction('alice: view details');
  await page.waitForLoadState('networkidle');

  const aliceCapture = aliceLogger.stop();

  // Create sequence
  const sequence = sequenceManager.createFromCapture(aliceCapture, {
    name: 'Resource Access Pattern',
    description: 'Access protected resource',
    testType: 'idor-candidate'
  });

  authManager.saveCapture(aliceCapture, 'alice');
  sequenceManager.saveRecording(sequence.id, aliceCapture, 'alice');

  // === PHASE 2: Replay sequence as Bob ===
  console.log('\n=== PHASE 2: REPLAYING AS BOB ===');
  const bobContext = await browser.newContext();
  const bobPage = await bobContext.newPage();
  const bobLogger = createActionAwareRequestLogger(bobPage, now);

  await sequenceManager.replay(bobPage, sequence.id, async (page, actions) => {
    for (const action of actions) {
      bobLogger.startAction(`bob: ${action.step.replace('alice:', '')}`);

      // Replay same URLs/actions but in Bob's context
      if (action.requests && action.requests.length > 0) {
        const primaryUrl = action.requests[0].url;
        await page.goto(primaryUrl);
        await page.waitForLoadState('networkidle');
      }
    }
  });

  const bobCapture = bobLogger.stop();
  authManager.saveCapture(bobCapture, 'bob');
  sequenceManager.saveRecording(sequence.id, bobCapture, 'bob');

  await bobContext.close();

  // === PHASE 3: Compare results ===
  console.log('\n=== PHASE 3: COMPARING RESPONSES ===');
  const recordings = sequenceManager.getRecordings(sequence.id);

  console.log(`\nAlice recorded: ${recordings.find(r => r.user === 'alice')?.actions} actions`);
  console.log(`Bob recorded: ${recordings.find(r => r.user === 'bob')?.actions} actions`);

  console.log('\n✓ Compare response codes/data to identify IDOR vulnerabilities');
  console.log('  200 OK in both users = potential IDOR');
  console.log('  200 OK (alice) + 403 Forbidden (bob) = proper authorization');
});

/* ---------- EXAMPLE 5: Using Interactive CLI ---------- */
test.skip('example-5: cli workflow demo', async () => {
  console.log(`
=== HOW TO USE INTERACTIVE CLI ===

1. Start the CLI:
   $ node scripts/playwright-session-manager.js

2. Configure Users:
   - Select option 1
   - Add alice, bob, etc.

3. View Saved Sequences:
   - Select option 2
   - See tree view of all sequences

4. Record New Sequence:
   - Select option 3
   - Enter sequence details
   - Run: npx playwright test --grep "record-mode" --headed
   - Use Playwright Inspector to step through actions

5. Replay Sequence:
   - Select option 4
   - Choose sequence and user
   - Run: npx playwright test --grep "replay-mode" --headed

6. Edit Sequence (Codium):
   - Select option 5
   - Choose sequence
   - Edit JSON in VSCodium
   - Save changes

7. Compare Recordings:
   - Select option 7
   - View all recordings for a sequence
   - Compare request/response data between users

=== DIRECTORY STRUCTURE ===

./auth-sessions/          # User sessions and captures
  ├── alice-session.json  # Cookies, localStorage, etc.
  ├── alice-capture.json  # Full request/response data
  └── bob-session.json

./saved-sequences/        # Sequence definitions
  ├── sequences.json      # All sequence metadata
  └── recordings/         # Full recording details
      ├── seq-123-alice-456.json
      └── seq-123-bob-789.json

=== IDOR TESTING WORKFLOW ===

1. Configure alice and bob via CLI
2. Record sequence as alice (legitimate access)
3. Replay sequence as bob (cross-user test)
4. Compare recordings to detect IDOR:
   - Same 200 OK = IDOR vulnerability
   - 403/404 for bob = proper authorization
5. Use recordings as evidence/documentation

  `);
});
