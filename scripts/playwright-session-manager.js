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
    this.usersFile = path.join(baseDir, 'users.json');
    this.profilesDir = path.join(baseDir, 'browser-profiles');
    this.users = new Map();

    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true });
    }
    if (!fs.existsSync(this.profilesDir)) {
      fs.mkdirSync(this.profilesDir, { recursive: true });
    }

    // Load persisted users
    this.loadUsers();
  }

  loadUsers() {
    if (fs.existsSync(this.usersFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(this.usersFile, 'utf8'));
        Object.entries(data.users || {}).forEach(([userId, userData]) => {
          this.users.set(userId, {
            ...userData,
            sessionFile: path.join(this.baseDir, `${userId}-session.json`),
            idsFile: path.join(this.baseDir, `${userId}-ids.json`)
          });
        });
      } catch (err) {
        console.warn(`⚠️  Failed to load users: ${err.message}`);
      }
    }
  }

  saveUsers() {
    const usersObj = {};
    this.users.forEach((userData, userId) => {
      // Save only credentials, not derived paths
      const { sessionFile, idsFile, ...credentials } = userData;
      usersObj[userId] = credentials;
    });

    fs.writeFileSync(this.usersFile, JSON.stringify({ users: usersObj }, null, 2));
  }

  addUser(userId, credentials) {
    this.users.set(userId, {
      ...credentials,
      sessionFile: path.join(this.baseDir, `${userId}-session.json`),
      idsFile: path.join(this.baseDir, `${userId}-ids.json`)
    });
    this.saveUsers();
    console.log(`✓ User ${userId} saved to: ${this.usersFile}`);
  }

  removeUser(userId) {
    if (!this.users.has(userId)) {
      throw new Error(`User ${userId} not found`);
    }
    this.users.delete(userId);
    this.saveUsers();
    console.log(`✓ User ${userId} removed`);
  }

  /**
   * Get persistent browser profile path for a user.
   * Use with browserType.launchPersistentContext() for Cloudflare-protected sites.
   *
   * Why persistent contexts:
   * - Preserves cookies (cf_clearance)
   * - Preserves localStorage/sessionStorage
   * - Preserves TLS fingerprint
   * - Preserves browser entropy
   * - Avoids Cloudflare verification loops
   *
   * This is the ONLY architecturally sound solution for Cloudflare.
   */
  getProfilePath(userId) {
    return path.join(this.profilesDir, userId);
  }

  /**
   * Launch a persistent browser context for a user.
   * Supports two modes:
   * - managed: Playwright creates and manages the profile (default)
   * - trusted: Use a pre-bootstrapped Chromium profile (for Cloudflare)
   *
   * Example:
   *   const context = await authManager.launchUserContext(chromium, 'alice');
   *   const page = context.pages()[0] || await context.newPage();
   */
  async launchUserContext(browserType, userId, options = {}) {
    if (!this.users.has(userId)) {
      throw new Error(`User ${userId} not configured`);
    }

    const user = this.users.get(userId);
    const profileConfig = user.browserProfile || { mode: 'managed' };

    // TRUSTED MODE: Use pre-bootstrapped browser profile
    if (profileConfig.mode === 'trusted') {
      const profilePath = profileConfig.path;

      // Fail fast if trusted profile doesn't exist
      if (!fs.existsSync(profilePath)) {
        throw new Error(
          `Trusted profile not found: ${profilePath}\n` +
          `Run: npm run cli → Bootstrap Trusted Profile → ${userId}`
        );
      }

      console.log(`🔐 Launching TRUSTED context for ${userId}`);
      console.log(`   Profile: ${profilePath}`);

      const context = await browserType.launchPersistentContext(profilePath, {
        headless: false,
        executablePath: '/usr/bin/chromium-browser',
        args: [
          '--disable-dev-shm-usage',
          '--no-sandbox',
          '--disable-blink-features=AutomationControlled',
          '--disable-features=IsolateOrigins,site-per-process'
        ],
        ...options
      });

      return context;
    }

    // MANAGED MODE: Playwright-owned profile (default)
    const profilePath = this.getProfilePath(userId);
    console.log(`🔐 Launching MANAGED context for ${userId}`);
    console.log(`   Profile: ${profilePath}`);

    const context = await browserType.launchPersistentContext(profilePath, {
      headless: false,
      executablePath: '/usr/bin/chromium-browser',
      args: [
        '--disable-dev-shm-usage',
        '--no-sandbox'
      ],
      ...options
    });

    return context;
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
    // CRITICAL VALIDATION: Fail loudly if recording is empty
    const totalRequests = buckets.reduce((sum, b) => sum + (b.requests?.length || 0), 0);

    if (buckets.length === 0) {
      throw new Error(
        'RECORDING VALIDATION FAILED:\n' +
        '  ✗ Zero action buckets captured\n' +
        '  ✗ Recording is completely empty\n' +
        '  → Possible causes:\n' +
        '    - Browser was blocked by Cloudflare\n' +
        '    - Network connectivity issues\n' +
        '    - No actions were performed\n' +
        '  → Solution: Check browser window for challenges/errors'
      );
    }

    if (totalRequests === 0) {
      throw new Error(
        'RECORDING VALIDATION FAILED:\n' +
        `  ✗ ${buckets.length} action(s) captured but ZERO HTTP requests\n` +
        '  ✗ Recording contains no network traffic\n' +
        '  → Possible causes:\n' +
        '    - Browser blocked by Cloudflare or network filter\n' +
        '    - Actions did not trigger any HTTP requests\n' +
        '    - Page navigation failed silently\n' +
        '  → Solution:\n' +
        '    - Check browser window during recording\n' +
        '    - For Cloudflare sites: use trusted profile mode\n' +
        '    - Verify actions actually load new content'
      );
    }

    const recordingFile = path.join(this.recordingsDir, `${sequenceId}-${user}-${Date.now()}.json`);
    fs.writeFileSync(recordingFile, JSON.stringify({
      sequenceId,
      user,
      timestamp: new Date().toISOString(),
      buckets,
      validation: {
        totalActions: buckets.length,
        totalRequests: totalRequests,
        validated: true
      }
    }, null, 2));

    console.log(`✓ Full recording saved: ${recordingFile}`);
    console.log(`  Actions: ${buckets.length}, Requests: ${totalRequests}`);
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

  // Generate Playwright test from recording
  generateTestFromRecording(recordingFile, options = {}) {
    const recording = JSON.parse(fs.readFileSync(recordingFile, 'utf8'));
    const { sequenceId, user, buckets } = recording;

    const testName = options.testName || `replay-${sequenceId}-${user}`;
    const testDescription = options.description || `Auto-generated from recording: ${path.basename(recordingFile)}`;

    const testCode = this._generateTestCode(testName, testDescription, buckets, user, options);

    const testFile = path.join(this.baseDir, `${testName}.spec.js`);
    fs.writeFileSync(testFile, testCode);

    console.log(`✓ Generated test: ${testFile}`);
    return testFile;
  }

  _generateTestCode(testName, description, buckets, originalUser, options = {}) {
    const multiUser = options.multiUser || false;
    const users = options.users || [originalUser];

    const imports = `const { test, expect } = require('@playwright/test');
const { AuthManager, createSessionClock, createActionAwareRequestLogger } = require('./playwright-session-manager');

/**
 * ${description}
 * Original user: ${originalUser}
 * Actions: ${buckets.length}
 * Generated: ${new Date().toISOString()}
 */
`;

    if (multiUser) {
      return this._generateMultiUserTest(testName, buckets, users, imports);
    } else {
      return this._generateSingleUserTest(testName, buckets, originalUser, imports);
    }
  }

  _generateSingleUserTest(testName, buckets, user, imports) {
    const actions = buckets.map((bucket, idx) => {
      const action = bucket.action;
      const requests = bucket.requests || [];
      const mainRequest = requests[0];

      if (!mainRequest) {
        return `  // Action ${idx + 1}: ${action}\n  // (no HTTP requests recorded)`;
      }

      const url = mainRequest.url;
      const method = mainRequest.method;

      return `  // Action ${idx + 1}: ${action}
  logger.startAction('${action}');
  await page.goto('${url}');
  await page.waitForLoadState('networkidle');`;
    }).join('\n\n');

    return `${imports}

test('${testName}', async ({ browser }) => {
  const authManager = new AuthManager();
  const { chromium } = require('playwright');

  // Launch user context
  const context = await authManager.launchUserContext(chromium, '${user}');
  const page = context.pages()[0] || await context.newPage();

  const now = createSessionClock();
  const logger = createActionAwareRequestLogger(page, now);

  try {
${actions}

    const capture = logger.stop();
    console.log(\`✓ Replay complete: \${capture.length} actions\`);

  } finally {
    await context.close();
  }
});
`;
  }

  _generateMultiUserTest(testName, buckets, users, imports) {
    const baseActions = buckets.map((bucket, idx) => {
      const action = bucket.action;
      const requests = bucket.requests || [];
      const mainRequest = requests[0];

      if (!mainRequest) {
        return `    // Action ${idx + 1}: ${action}\n    // (no HTTP requests recorded)`;
      }

      const url = mainRequest.url;
      return `    // Action ${idx + 1}: ${action}
    logger.startAction('[USER-\${user}] ${action}');
    await page.goto('${url}');
    await page.waitForLoadState('networkidle');`;
    }).join('\n\n');

    const userTests = users.map(user => `
  // Test with user: ${user}
  console.log('\\n=== Testing with user: ${user} ===');
  const context_${user} = await authManager.launchUserContext(chromium, '${user}');
  const page_${user} = context_${user}.pages()[0] || await context_${user}.newPage();
  const logger_${user} = createActionAwareRequestLogger(page_${user}, now);

  try {
    const user = '${user}';
    const page = page_${user};
    const logger = logger_${user};

${baseActions}

    const capture = logger.stop();
    recordings.push({ user: '${user}', capture });
    console.log(\`✓ User ${user}: \${capture.length} actions captured\`);

  } finally {
    await context_${user}.close();
  }
`).join('\n');

    return `${imports}

test('${testName} - multi-user IDOR test', async () => {
  const authManager = new AuthManager();
  const { chromium } = require('playwright');
  const now = createSessionClock();
  const recordings = [];

${userTests}

  // Compare recordings for IDOR issues
  console.log('\\n=== IDOR Analysis ===');
  console.log(\`Recorded \${recordings.length} user sessions\`);

  // TODO: Add automated IDOR comparison logic here
  // Compare recordings[0].capture with recordings[1].capture
  // Look for unauthorized access patterns
});
`;
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
      console.log('8. Bootstrap Trusted Profile');
      console.log('9. Generate Test from Recording');
      console.log('0. Exit');
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
          await this.bootstrapTrustedProfile();
          break;
        case '9':
          await this.generateTestFromRecording();
          break;
        case '0':
          console.log('Goodbye!');
          this.rl.close();
          return;
        default:
          console.log('Invalid option');
      }
    }
  }

  async configureUsers() {
    console.log('\n=== CONFIGURE USERS (Persistent) ===');
    const userIds = this.authManager.getUserIds();
    console.log('Current users:', userIds.join(', ') || '(none)');
    console.log('\n1. Add User');
    console.log('2. Remove User');
    console.log('3. Configure Browser Profile Mode');
    console.log('4. Back to Main Menu');

    const choice = await this.prompt('\nSelect option: ');

    if (choice === '1') {
      const userId = await this.prompt('User ID (e.g., alice): ');
      if (!userId) return;

      const email = await this.prompt('Email: ');
      const password = await this.prompt('Password: ');

      this.authManager.addUser(userId, { email, password });
    } else if (choice === '2') {
      if (userIds.length === 0) {
        console.log('❌ No users to remove');
        return;
      }

      const userId = await this.prompt('User ID to remove: ');
      if (!userId) return;

      try {
        this.authManager.removeUser(userId);
      } catch (err) {
        console.log(`❌ ${err.message}`);
      }
    } else if (choice === '3') {
      await this.configureBrowserProfile();
    }
  }

  async configureBrowserProfile() {
    console.log('\n=== CONFIGURE BROWSER PROFILE MODE ===');
    const userIds = this.authManager.getUserIds();

    if (userIds.length === 0) {
      console.log('❌ No users configured. Add a user first.');
      return;
    }

    console.log('Available users:', userIds.join(', '));
    const userId = await this.prompt('\nUser ID to configure: ');

    if (!this.authManager.users.has(userId)) {
      console.log('❌ User not found');
      return;
    }

    const user = this.authManager.users.get(userId);
    const currentMode = user.browserProfile?.mode || 'managed';

    console.log(`\nCurrent mode: ${currentMode}`);
    console.log('\nSelect browser profile mode:');
    console.log('1. Managed (Playwright-managed, automatic)');
    console.log('2. Trusted (pre-configured Chromium profile for Cloudflare)');

    const modeChoice = await this.prompt('\nChoice: ');

    if (modeChoice === '1') {
      user.browserProfile = { mode: 'managed' };
      this.authManager.saveUsers();
      console.log('✓ Browser profile mode set to: managed');
    } else if (modeChoice === '2') {
      // Auto-generate default path based on user ID
      const defaultPath = `/home/${process.env.USER}/.cf-trusted-profile-${userId}`;

      console.log(`\nDefault trusted profile path: ${defaultPath}`);
      console.log('1. Use default path');
      console.log('2. Enter custom path');

      const pathChoice = await this.prompt('\nChoice: ');

      let profilePath;
      if (pathChoice === '1' || !pathChoice) {
        profilePath = defaultPath;
      } else if (pathChoice === '2') {
        profilePath = await this.prompt('Enter custom path: ');
        if (!profilePath) {
          console.log('❌ Path required for trusted mode');
          return;
        }
      } else {
        console.log('❌ Invalid choice');
        return;
      }

      user.browserProfile = {
        mode: 'trusted',
        path: profilePath
      };
      this.authManager.saveUsers();
      console.log('✓ Browser profile mode set to: trusted');
      console.log(`   Path: ${profilePath}`);
      console.log('\n⚠️  You must bootstrap this profile before use:');
      console.log('   Main Menu → Bootstrap Trusted Profile');
    } else {
      console.log('❌ Invalid choice');
    }
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

  async bootstrapTrustedProfile() {
    console.log('\n=== BOOTSTRAP TRUSTED PROFILE ===');
    console.log('This will launch Chromium for manual setup of a trusted profile.');
    console.log('Use this to solve Cloudflare challenges and establish browser trust.\n');

    const userIds = this.authManager.getUserIds();
    if (userIds.length === 0) {
      console.log('❌ No users configured. Add a user first.');
      return;
    }

    // Show users in trusted mode
    const trustedUsers = [];
    this.authManager.users.forEach((user, userId) => {
      if (user.browserProfile?.mode === 'trusted') {
        trustedUsers.push({ userId, path: user.browserProfile.path });
      }
    });

    if (trustedUsers.length === 0) {
      console.log('❌ No users configured with trusted profile mode.');
      console.log('   Configure a user first: Main Menu → Configure Users → Configure Browser Profile Mode');
      return;
    }

    console.log('Users in trusted mode:');
    trustedUsers.forEach((u, idx) => {
      console.log(`${idx + 1}. ${u.userId} → ${u.path}`);
    });

    const choice = await this.prompt('\nSelect user (number): ');
    const selectedIdx = parseInt(choice) - 1;

    if (selectedIdx < 0 || selectedIdx >= trustedUsers.length) {
      console.log('❌ Invalid selection');
      return;
    }

    const selected = trustedUsers[selectedIdx];

    console.log(`\n✓ Launching Chromium with profile: ${selected.path}`);
    console.log('\n=== INSTRUCTIONS ===');
    console.log('1. Solve any Cloudflare challenges');
    console.log('2. Log into your target site (GitLab, etc.)');
    console.log('3. Browse a few pages to establish history');
    console.log('4. Close the browser window when done');
    console.log('====================\n');

    await this.prompt('Press Enter to launch Chromium...');

    // Create profile directory if it doesn't exist
    if (!fs.existsSync(selected.path)) {
      fs.mkdirSync(selected.path, { recursive: true });
      console.log(`✓ Created profile directory: ${selected.path}`);
    }

    // Launch Chromium
    const chromium = spawn('chromium-browser', [
      `--user-data-dir=${selected.path}`,
      '--no-sandbox',
      '--disable-dev-shm-usage'
    ], {
      stdio: 'inherit',
      shell: false
    });

    await new Promise((resolve) => {
      chromium.on('close', (code) => {
        console.log(`\n✓ Chromium closed (exit code: ${code})`);
        resolve();
      });
    });

    console.log('\n✓ Bootstrap complete. Profile ready for automation.');
    console.log(`   User "${selected.userId}" can now use this trusted profile.`);
  }

  async generateTestFromRecording() {
    console.log('\n=== GENERATE TEST FROM RECORDING ===');

    const recordings = fs.readdirSync(this.sequenceManager.recordingsDir)
      .filter(f => f.endsWith('.json'))
      .map(f => path.join(this.sequenceManager.recordingsDir, f));

    if (recordings.length === 0) {
      console.log('❌ No recordings found.\n');
      return;
    }

    console.log('\nAvailable recordings:\n');
    recordings.forEach((rec, idx) => {
      try {
        const data = JSON.parse(fs.readFileSync(rec, 'utf8'));
        console.log(`[${idx + 1}] ${path.basename(rec)}`);
        console.log(`    User: ${data.user}, Actions: ${data.buckets.length}, Time: ${data.timestamp}`);
      } catch (e) {
        console.log(`[${idx + 1}] ${path.basename(rec)} (error reading)`);
      }
    });

    const choice = await this.prompt('\nSelect recording: ');
    const idx = parseInt(choice) - 1;

    if (idx < 0 || idx >= recordings.length) {
      console.log('❌ Invalid selection\n');
      return;
    }

    const selectedRecording = recordings[idx];
    const recordingData = JSON.parse(fs.readFileSync(selectedRecording, 'utf8'));

    console.log('\nTest type:');
    console.log('1) Single user (replay as original user)');
    console.log('2) Multi-user (replay with multiple users for IDOR testing)');

    const typeChoice = await this.prompt('\nChoice: ');

    if (typeChoice === '1') {
      const testFile = this.sequenceManager.generateTestFromRecording(selectedRecording, {
        testName: `replay-${recordingData.sequenceId}-${recordingData.user}`,
        description: `Replay recording for user ${recordingData.user}`
      });

      console.log(`\n✓ Test generated: ${testFile}`);
      console.log('\nRun with: npx playwright test\n');

    } else if (typeChoice === '2') {
      const userIds = this.authManager.getUserIds();
      console.log(`\nAvailable users: ${userIds.join(', ')}`);

      const usersInput = await this.prompt('Enter user IDs (comma-separated): ');
      const users = usersInput.split(',').map(u => u.trim()).filter(u => u);

      if (users.length < 2) {
        console.log('❌ Multi-user tests require at least 2 users\n');
        return;
      }

      const testFile = this.sequenceManager.generateTestFromRecording(selectedRecording, {
        testName: `multi-user-idor-${recordingData.sequenceId}`,
        description: `Multi-user IDOR test for ${recordingData.sequenceId}`,
        multiUser: true,
        users: users
      });

      console.log(`\n✓ Multi-user test generated: ${testFile}`);
      console.log(`  Users: ${users.join(', ')}`);
      console.log('\nRun with: npx playwright test\n');

    } else {
      console.log('❌ Invalid choice\n');
    }
  }
}

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
