const { test, chromium } = require('@playwright/test');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');

/* ---------- session clock ---------- */
function createSessionClock() {
  const start = Date.now();
  return () => ((Date.now() - start) / 1000).toFixed(3);
}

/* ---------- action-aware request logger ---------- */
function createActionAwareRequestLogger(page, now) {
  let currentAction = null;
  const buckets = [];

  page.on('request', request => {
    if (!currentAction) return;

    buckets[buckets.length - 1].requests.push({
      method: request.method(),
      url: request.url(),
      headers: request.headers(),
      postData: request.postData()
    });
  });

  page.on('response', async response => {
    if (!currentAction) return;

    const bucket = buckets[buckets.length - 1];
    const req = bucket.requests[bucket.requests.length - 1];
    if (req && req.url === response.url()) {
      req.status = response.status();
      req.responseHeaders = response.headers();
      try {
        req.responseBody = await response.text();
      } catch (e) {
        req.responseBody = '<binary or failed to read>';
      }
    }
  });

  function startAction(label) {
    const t = now();
    currentAction = label;
    buckets.push({
      action: label,
      t_start_sec: t,
      requests: []
    });
    console.log(`\n[ACTION START] +${t}s  ${label}`);
  }

  function stop() {
    currentAction = null;
    return buckets;
  }

  return { startAction, stop };
}

/* ---------- Multi-User Auth Manager ---------- */
class AuthManager {
  constructor(baseDir = './auth-sessions') {
    this.baseDir = baseDir;
    this.users = new Map();
    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
    }
  }

  addUser(userId, credentials) {
    this.users.set(userId, {
      ...credentials,
      sessionFile: path.join(this.baseDir, `${userId}-session.json`),
      idsFile: path.join(this.baseDir, `${userId}-ids.json`),
      captureFile: path.join(this.baseDir, `${userId}-capture.json`)
    });
  }

  async login(page, userId, loginFn) {
    const user = this.users.get(userId);
    if (!user) throw new Error(`User ${userId} not configured`);

    console.log(`\n=== LOGGING IN AS: ${userId} ===`);

    await loginFn(page, user);

    const cookies = await page.context().cookies();
    const localStorage = await page.evaluate(() => JSON.stringify(localStorage));
    const sessionStorage = await page.evaluate(() => JSON.stringify(sessionStorage));

    fs.writeFileSync(user.sessionFile, JSON.stringify({
      cookies,
      localStorage,
      sessionStorage,
      timestamp: new Date().toISOString()
    }, null, 2));

    console.log(`✓ Session saved: ${user.sessionFile}`);
    return user;
  }

  async loadSession(page, userId) {
    const user = this.users.get(userId);
    if (!user) throw new Error(`User ${userId} not configured`);

    if (!fs.existsSync(user.sessionFile)) {
      throw new Error(`No saved session for ${userId}. Run login first.`);
    }

    const session = JSON.parse(fs.readFileSync(user.sessionFile, 'utf8'));

    await page.context().addCookies(session.cookies);

    await page.goto('about:blank');
    await page.evaluate((data) => {
      const local = JSON.parse(data.localStorage);
      const session = JSON.parse(data.sessionStorage);

      Object.entries(local).forEach(([k, v]) => localStorage.setItem(k, v));
      Object.entries(session).forEach(([k, v]) => sessionStorage.setItem(k, v));
    }, session);

    console.log(`✓ Session loaded: ${userId} (saved ${session.timestamp})`);
    return user;
  }

  getUserIds() {
    return Array.from(this.users.keys());
  }

  saveCapture(buckets, userId) {
    const user = this.users.get(userId);
    fs.writeFileSync(user.captureFile, JSON.stringify(buckets, null, 2));
    console.log(`✓ Full capture saved: ${user.captureFile}`);
  }
}

/* ---------- Sequence Manager (Saved Box) ---------- */
class SequenceManager {
  constructor(baseDir = './saved-sequences') {
    this.baseDir = baseDir;
    this.sequencesFile = path.join(baseDir, 'sequences.json');
    this.recordingsDir = path.join(baseDir, 'recordings');

    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
    }
    if (!fs.existsSync(this.recordingsDir)) {
      fs.mkdirSync(this.recordingsDir, { recursive: true });
    }

    this.sequences = this.load();
  }

  load() {
    if (fs.existsSync(this.sequencesFile)) {
      return JSON.parse(fs.readFileSync(this.sequencesFile, 'utf8'));
    }
    return { sequences: [] };
  }

  save() {
    fs.writeFileSync(this.sequencesFile, JSON.stringify(this.sequences, null, 2));
  }

  list() {
    return this.sequences.sequences;
  }

  get(id) {
    return this.sequences.sequences.find(s => s.id === id);
  }

  add(sequence) {
    if (!sequence.id) {
      sequence.id = `seq-${Date.now()}`;
    }
    this.sequences.sequences.push(sequence);
    this.save();
    console.log(`✓ Sequence saved: ${sequence.id}`);
    return sequence.id;
  }

  update(id, updates) {
    const idx = this.sequences.sequences.findIndex(s => s.id === id);
    if (idx === -1) throw new Error(`Sequence ${id} not found`);

    this.sequences.sequences[idx] = { ...this.sequences.sequences[idx], ...updates };
    this.save();
    console.log(`✓ Sequence updated: ${id}`);
  }

  delete(id) {
    this.sequences.sequences = this.sequences.sequences.filter(s => s.id !== id);
    this.save();
    console.log(`✓ Sequence deleted: ${id}`);
  }

  // Convert action logger output to user-agnostic sequence
  createFromCapture(buckets, metadata = {}) {
    const actions = buckets.map((bucket, idx) => ({
      step: bucket.action,
      t_start_sec: bucket.t_start_sec,
      requests: bucket.requests.map(r => ({
        method: r.method,
        url: r.url,
        status: r.status
      }))
    }));

    const sequence = {
      id: metadata.id || `seq-${Date.now()}`,
      name: metadata.name || 'Untitled Sequence',
      description: metadata.description || '',
      created: new Date().toISOString(),
      actions: actions,
      metadata: {
        totalActions: actions.length,
        totalRequests: buckets.reduce((sum, b) => sum + b.requests.length, 0),
        ...metadata
      }
    };

    this.add(sequence);
    return sequence;
  }

  // Save full recording with all details
  saveRecording(sequenceId, buckets, user) {
    const recordingFile = path.join(this.recordingsDir, `${sequenceId}-${user}-${Date.now()}.json`);
    fs.writeFileSync(recordingFile, JSON.stringify({
      sequenceId,
      user,
      timestamp: new Date().toISOString(),
      buckets
    }, null, 2));
    console.log(`✓ Full recording saved: ${recordingFile}`);
    return recordingFile;
  }

  // Get all recordings for a sequence
  getRecordings(sequenceId) {
    const files = fs.readdirSync(this.recordingsDir)
      .filter(f => f.startsWith(sequenceId))
      .map(f => path.join(this.recordingsDir, f));

    return files.map(f => {
      const data = JSON.parse(fs.readFileSync(f, 'utf8'));
      return {
        file: f,
        user: data.user,
        timestamp: data.timestamp,
        actions: data.buckets.length
      };
    });
  }

  // Replay a sequence with a specific user
  async replay(page, sequenceId, replayFn) {
    const sequence = this.get(sequenceId);
    if (!sequence) throw new Error(`Sequence ${sequenceId} not found`);

    console.log(`\n=== REPLAYING SEQUENCE: ${sequence.name} ===`);
    console.log(`Actions: ${sequence.actions.length}`);

    // Execute the replay function with sequence actions
    await replayFn(page, sequence.actions);

    console.log(`✓ Sequence replay complete: ${sequenceId}`);
  }

  // Display tree view of sequences
  displayTree() {
    console.log('\n=== SAVED SEQUENCES (Tree View) ===\n');

    if (this.sequences.sequences.length === 0) {
      console.log('  (empty - no sequences saved)\n');
      return;
    }

    this.sequences.sequences.forEach((seq, idx) => {
      const prefix = idx === this.sequences.sequences.length - 1 ? '└──' : '├──';
      console.log(`${prefix} [${seq.id}] ${seq.name}`);
      console.log(`    │   Description: ${seq.description || '(none)'}`);
      console.log(`    │   Created: ${seq.created}`);
      console.log(`    │   Actions: ${seq.actions.length}`);

      // Show first 3 actions
      seq.actions.slice(0, 3).forEach((action, actionIdx) => {
        const actionPrefix = actionIdx === Math.min(seq.actions.length - 1, 2) ? '    └──' : '    ├──';
        console.log(`${actionPrefix} ${actionIdx + 1}. ${action.step}`);
      });

      if (seq.actions.length > 3) {
        console.log(`    └── ... (${seq.actions.length - 3} more actions)`);
      }
      console.log('');
    });
  }
}

/* ---------- Interactive CLI Menu ---------- */
class InteractiveCLI {
  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    this.authManager = new AuthManager();
    this.sequenceManager = new SequenceManager();
  }

  async prompt(question) {
    return new Promise(resolve => {
      this.rl.question(question, answer => {
        resolve(answer.trim());
      });
    });
  }

  async mainMenu() {
    while (true) {
      console.log('\n========================================');
      console.log('  PLAYWRIGHT SESSION MANAGER');
      console.log('========================================');
      console.log('1. Configure Users');
      console.log('2. View Saved Sequences (Tree)');
      console.log('3. Record New Sequence');
      console.log('4. Replay Sequence');
      console.log('5. Edit Sequence (Codium)');
      console.log('6. Delete Sequence');
      console.log('7. Compare Recordings');
      console.log('8. Exit');
      console.log('========================================');

      const choice = await this.prompt('Select option: ');

      switch (choice) {
        case '1':
          await this.configureUsers();
          break;
        case '2':
          this.sequenceManager.displayTree();
          await this.prompt('Press Enter to continue...');
          break;
        case '3':
          await this.recordSequence();
          break;
        case '4':
          await this.replaySequence();
          break;
        case '5':
          await this.editSequence();
          break;
        case '6':
          await this.deleteSequence();
          break;
        case '7':
          await this.compareRecordings();
          break;
        case '8':
          console.log('Goodbye!');
          this.rl.close();
          return;
        default:
          console.log('Invalid option');
      }
    }
  }

  async configureUsers() {
    console.log('\n=== CONFIGURE USERS ===');
    console.log('Current users:', this.authManager.getUserIds().join(', ') || '(none)');

    const userId = await this.prompt('User ID (e.g., alice): ');
    if (!userId) return;

    const email = await this.prompt('Email: ');
    const password = await this.prompt('Password: ');

    this.authManager.addUser(userId, { email, password });
    console.log(`✓ User ${userId} configured`);
  }

  async recordSequence() {
    console.log('\n=== RECORD NEW SEQUENCE ===');
    console.log('Note: This will launch a browser for interactive recording');
    console.log('Tip: Use page.pause() gates to step through actions\n');

    const name = await this.prompt('Sequence name: ');
    const description = await this.prompt('Description: ');
    const userId = await this.prompt('Record as user (e.g., alice): ');

    if (!this.authManager.users.has(userId)) {
      console.log(`❌ User ${userId} not configured. Configure users first.`);
      return;
    }

    console.log('\n✓ Recording will start. Use Playwright Inspector to approve each action.');
    console.log('  The script will generate this for you to customize.\n');

    // Save metadata for the recording script to pick up
    const recordingConfig = {
      name,
      description,
      userId,
      timestamp: new Date().toISOString()
    };

    fs.writeFileSync('.recording-config.json', JSON.stringify(recordingConfig, null, 2));
    console.log('✓ Config saved. Run: npx playwright test --grep "record-mode"');
  }

  async replaySequence() {
    console.log('\n=== REPLAY SEQUENCE ===');
    this.sequenceManager.displayTree();

    const sequenceId = await this.prompt('\nSequence ID to replay: ');
    const sequence = this.sequenceManager.get(sequenceId);

    if (!sequence) {
      console.log('❌ Sequence not found');
      return;
    }

    console.log('\nAvailable users:', this.authManager.getUserIds().join(', '));
    const userId = await this.prompt('Replay as user: ');

    if (!this.authManager.users.has(userId)) {
      console.log('❌ User not configured');
      return;
    }

    // Save replay config
    const replayConfig = {
      sequenceId,
      userId,
      timestamp: new Date().toISOString()
    };

    fs.writeFileSync('.replay-config.json', JSON.stringify(replayConfig, null, 2));
    console.log('✓ Config saved. Run: npx playwright test --grep "replay-mode"');
  }

  async editSequence() {
    console.log('\n=== EDIT SEQUENCE (Codium) ===');
    this.sequenceManager.displayTree();

    const sequenceId = await this.prompt('\nSequence ID to edit: ');
    const sequence = this.sequenceManager.get(sequenceId);

    if (!sequence) {
      console.log('❌ Sequence not found');
      return;
    }

    // Create temp file for editing
    const tempFile = path.join(this.sequenceManager.baseDir, `${sequenceId}.edit.json`);
    fs.writeFileSync(tempFile, JSON.stringify(sequence, null, 2));

    console.log(`\n✓ Opening ${tempFile} in VSCodium...`);

    // Launch codium
    const codium = spawn('codium', [tempFile, '--wait'], {
      stdio: 'inherit',
      shell: true
    });

    await new Promise((resolve) => {
      codium.on('close', resolve);
    });

    // Check if file was modified
    if (fs.existsSync(tempFile)) {
      const answer = await this.prompt('Save changes? (y/n): ');
      if (answer.toLowerCase() === 'y') {
        const updated = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
        this.sequenceManager.update(sequenceId, updated);
        console.log('✓ Sequence updated');
      }
      fs.unlinkSync(tempFile);
    }
  }

  async deleteSequence() {
    console.log('\n=== DELETE SEQUENCE ===');
    this.sequenceManager.displayTree();

    const sequenceId = await this.prompt('\nSequence ID to delete: ');
    const confirm = await this.prompt(`Delete ${sequenceId}? (y/n): `);

    if (confirm.toLowerCase() === 'y') {
      this.sequenceManager.delete(sequenceId);
      console.log('✓ Sequence deleted');
    }
  }

  async compareRecordings() {
    console.log('\n=== COMPARE RECORDINGS ===');
    this.sequenceManager.displayTree();

    const sequenceId = await this.prompt('\nSequence ID: ');
    const recordings = this.sequenceManager.getRecordings(sequenceId);

    if (recordings.length === 0) {
      console.log('❌ No recordings found for this sequence');
      return;
    }

    console.log('\nRecordings:');
    recordings.forEach((rec, idx) => {
      console.log(`${idx + 1}. User: ${rec.user}, Time: ${rec.timestamp}, Actions: ${rec.actions}`);
    });

    console.log('\n✓ Use external diff tool to compare files');
    console.log(`   Location: ${this.sequenceManager.recordingsDir}/`);
  }
}

/* ---------- PLAYWRIGHT TESTS ---------- */

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

    authManager.saveCapture(capture, config.userId);
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

/* ---------- CLI ENTRY POINT ---------- */
if (require.main === module) {
  const cli = new InteractiveCLI();
  cli.mainMenu().catch(console.error);
}

module.exports = {
  createSessionClock,
  createActionAwareRequestLogger,
  AuthManager,
  SequenceManager,
  InteractiveCLI
};
