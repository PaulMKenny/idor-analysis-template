/**
 * Playwright Session Manager - Test Suite
 *
 * These tests work with the InteractiveCLI to enable recording and replay workflows.
 * Uses PERSISTENT CONTEXTS to avoid Cloudflare verification loops.
 */

const { test, chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const {
  createSessionClock,
  createActionAwareRequestLogger,
  AuthManager,
  SequenceManager
} = require('./playwright-session-manager');

test('record-mode @manual', async () => {
  // Check for recording config
  if (!fs.existsSync('.recording-config.json')) {
    console.log('❌ No recording config found. Run interactive CLI first.');
    return;
  }

  const config = JSON.parse(fs.readFileSync('.recording-config.json', 'utf8'));
  console.log('\n=== RECORDING MODE ===');
  console.log(`Name: ${config.name}`);
  console.log(`User: ${config.userId}`);

  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();

  // ✓ IMPORTANT: Use persistent context to avoid Cloudflare loops
  const context = await authManager.launchUserContext(chromium, config.userId);
  const page = context.pages()[0] || await context.newPage();

  const logger = createActionAwareRequestLogger(page, now);

  // Auto-start first action to capture all HTTP traffic
  logger.startAction('Initial navigation');

  console.log('\n=== INTERACTIVE RECORDING ===');
  console.log('Instructions:');
  console.log('1. Perform your workflow in the browser');
  console.log('2. Press CTRL+C in the Inspector to mark action boundaries (optional)');
  console.log('3. Close the Inspector when done');
  console.log('================================\n');

  // Pause for user to perform actions
  await page.pause();
  console.log('\n✓ Recording stopped. Processing...');

  const capture = logger.stop();
  const sequence = sequenceManager.createFromCapture(capture, {
    name: config.name,
    description: config.description
  });

  sequenceManager.saveRecording(sequence.id, capture, config.userId);

  console.log(`\n✓ Sequence recorded: ${sequence.id}`);

  await context.close();
  fs.unlinkSync('.recording-config.json');
});

test('replay-mode @manual', async () => {
  if (!fs.existsSync('.replay-config.json')) {
    console.log('❌ No replay config found. Run interactive CLI first.');
    return;
  }

  const config = JSON.parse(fs.readFileSync('.replay-config.json', 'utf8'));
  console.log('\n=== REPLAY MODE ===');
  console.log(`Sequence: ${config.sequenceId}`);
  console.log(`User: ${config.userId}`);

  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();

  // ✓ IMPORTANT: Use persistent context to avoid Cloudflare loops
  const context = await authManager.launchUserContext(chromium, config.userId);
  const page = context.pages()[0] || await context.newPage();

  const logger = createActionAwareRequestLogger(page, now);

  // Replay sequence
  await sequenceManager.replay(page, config.sequenceId, async (page, actions) => {
    console.log('\n=== REPLAYING ACTIONS ===');
    for (const action of actions) {
      logger.startAction(action.step);
      console.log(`Executing: ${action.step}`);
      // Here you'll need to implement actual action execution
      // This is user-defined based on your app
      await page.pause(); // For now, manual stepping
    }
  });

  const capture = logger.stop();
  sequenceManager.saveRecording(config.sequenceId, capture, config.userId);

  console.log('\n✓ Replay complete');

  await context.close();
  fs.unlinkSync('.replay-config.json');
});

test('example: full workflow @demo', async () => {
  const now = createSessionClock();
  const authManager = new AuthManager();
  const sequenceManager = new SequenceManager();

  // Configure users
  authManager.addUser('alice', { email: 'alice@example.com', password: 'pass1' });
  authManager.addUser('bob', { email: 'bob@example.com', password: 'pass2' });

  // ✓ Record Alice's sequence with persistent context
  const aliceContext = await authManager.launchUserContext(chromium, 'alice');
  const alicePage = aliceContext.pages()[0] || await aliceContext.newPage();
  const aliceLogger = createActionAwareRequestLogger(alicePage, now);

  aliceLogger.startAction('goto wikipedia');
  await alicePage.goto('https://www.wikipedia.org/');

  aliceLogger.startAction('fill search');
  await alicePage.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('playwright');

  aliceLogger.startAction('click search');
  await alicePage.getByRole('button', { name: 'Search' }).click();
  await alicePage.waitForURL('**/wiki/**');

  const aliceCapture = aliceLogger.stop();

  // Create sequence from Alice's actions
  const sequence = sequenceManager.createFromCapture(aliceCapture, {
    name: 'Wikipedia Search',
    description: 'Search for a term on Wikipedia'
  });

  sequenceManager.saveRecording(sequence.id, aliceCapture, 'alice');

  console.log(`\n✓ Sequence created: ${sequence.id}`);
  await aliceContext.close();

  // ✓ Replay with Bob using persistent context
  const bobContext = await authManager.launchUserContext(chromium, 'bob');
  const bobPage = bobContext.pages()[0] || await bobContext.newPage();
  const bobLogger = createActionAwareRequestLogger(bobPage, now);

  console.log('\n=== REPLAYING AS BOB ===');
  await sequenceManager.replay(bobPage, sequence.id, async (page, actions) => {
    for (const action of actions) {
      bobLogger.startAction(action.step);
      console.log(`Bob executing: ${action.step}`);

      // Re-execute actions (simplified replay logic)
      if (action.step === 'goto wikipedia') {
        await page.goto('https://www.wikipedia.org/');
      } else if (action.step === 'fill search') {
        await page.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('javascript');
      } else if (action.step === 'click search') {
        await page.getByRole('button', { name: 'Search' }).click();
        await page.waitForURL('**/wiki/**');
      }
    }
  });

  const bobCapture = bobLogger.stop();
  sequenceManager.saveRecording(sequence.id, bobCapture, 'bob');

  await bobContext.close();

  // Display tree
  sequenceManager.displayTree();

  // Show recordings
  console.log('\n=== RECORDINGS FOR SEQUENCE ===');
  const recordings = sequenceManager.getRecordings(sequence.id);
  recordings.forEach(rec => {
    console.log(`  User: ${rec.user}, Time: ${rec.timestamp}, File: ${path.basename(rec.file)}`);
  });
});
