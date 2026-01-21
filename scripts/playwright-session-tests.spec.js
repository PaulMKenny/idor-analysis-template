/**
 * Playwright Session Manager - Test Suite
 *
 * These tests work with the InteractiveCLI to enable recording and replay workflows.
 * Separated from the library file to follow proper Playwright test architecture.
 */

const { test } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const {
  createSessionClock,
  createActionAwareRequestLogger,
  AuthManager,
  SequenceManager
} = require('./playwright-session-manager');

test.describe('Recording and Replay', () => {

  test('record-mode @manual', async ({ page }) => {
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
    const logger = createActionAwareRequestLogger(page, now);

    // Load config from somewhere (you'll customize this)
    // For now, just pause to let user perform actions
    await page.pause();
    console.log('\n✓ Recording stopped. Processing...');

    const capture = logger.stop();
    const sequence = sequenceManager.createFromCapture(capture, {
      name: config.name,
      description: config.description
    });

    sequenceManager.saveRecording(sequence.id, capture, config.userId);

    console.log(`\n✓ Sequence recorded: ${sequence.id}`);
    fs.unlinkSync('.recording-config.json');
  });

  test('replay-mode @manual', async ({ page }) => {
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
    const logger = createActionAwareRequestLogger(page, now);

    // Load user session
    await authManager.loadSession(page, config.userId);

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
    fs.unlinkSync('.replay-config.json');
  });

  test('example: full workflow @demo', async ({ page, browser }) => {
    const now = createSessionClock();
    const authManager = new AuthManager();
    const sequenceManager = new SequenceManager();

    // Configure users
    authManager.addUser('alice', { email: 'alice@example.com', password: 'pass1' });
    authManager.addUser('bob', { email: 'bob@example.com', password: 'pass2' });

    // Record Alice's sequence
    const aliceLogger = createActionAwareRequestLogger(page, now);

    aliceLogger.startAction('goto wikipedia');
    await page.goto('https://www.wikipedia.org/');

    aliceLogger.startAction('fill search');
    await page.getByRole('searchbox', { name: 'Search Wikipedia' }).fill('playwright');

    aliceLogger.startAction('click search');
    await page.getByRole('button', { name: 'Search' }).click();
    await page.waitForURL('**/wiki/**');

    const aliceCapture = aliceLogger.stop();

    // Create sequence from Alice's actions
    const sequence = sequenceManager.createFromCapture(aliceCapture, {
      name: 'Wikipedia Search',
      description: 'Search for a term on Wikipedia'
    });

    sequenceManager.saveRecording(sequence.id, aliceCapture, 'alice');

    console.log(`\n✓ Sequence created: ${sequence.id}`);

    // Now replay with Bob (new context)
    const bobContext = await browser.newContext();
    const bobPage = await bobContext.newPage();
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
});
