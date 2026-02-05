# IDOR Interface + UI Automation Integration Guide

This repository now integrates three workflow modes in a single interface.

## Three Navigation Modes

The main interface (`./scripts/idor_interface.py`) provides three modes accessible via the `m` (toggle mode) command:

```
project → session → ui_automation → project → ...
```

### Mode 1: PROJECT

Root-level project operations and file browsing.

```
=== idor-analysis-template IDOR INTERFACE ===
Mode: PROJECT

3) Browse tree & save path
c) Open saved item in Codium
m) Toggle navigation mode (project / session / ui_automation)
s) Show saved box
q) Quit
```

**Use cases:**
- Browse project structure
- Save important files/directories
- Quick access to project docs

### Mode 2: SESSION

IDOR analysis workflows using Burp Suite XML exports.

```
=== idor-analysis-template IDOR INTERFACE ===
Mode: SESSION

1) Create new session
2) List sessions
3) Browse tree & save path
4) Run IDOR analyzer
5) Dump raw HTTP history
6) Run IDOR permutator (single message)
c) Open saved item in Codium
m) Toggle navigation mode (project / session / ui_automation)
s) Show saved box
q) Quit
```

**Use cases:**
- Analyze Burp XML captures
- Extract IDOR candidates
- Generate mutation permutations
- Traditional static IDOR analysis

### Mode 3: UI_AUTOMATION

Playwright-based multi-user session recording and replay.

```
=== idor-analysis-template IDOR INTERFACE ===
Mode: UI_AUTOMATION

1) Configure Playwright users
2) List sequences
3) Browse tree & save path
4) Execute saved sequence
c) Open saved item in Codium
m) Toggle navigation mode (project / session / ui_automation)
s) Show saved box
q) Quit
```

**Use cases:**
- Multi-user testing workflows
- Record user journeys
- Replay with different users
- Dynamic IDOR testing (live browser)

## Key Feature: User-Tracked Saved Box

The saved box in `UI_AUTOMATION` mode tracks which user owns each item:

```
> s

=== UI AUTOMATION SAVED BOX ===

----User alice:
  [1] sequences.json
  [2] recordings/seq-123-alice-456.json

----User bob:
  [1] recordings/seq-123-bob-789.json
```

In `PROJECT` and `SESSION` modes, the saved box is a simple list:

```
=== SESSION SAVED BOX ===
[1] sessions/session_1/input/history_1.xml
[2] sessions/session_1/output/idor_candidates.csv
```

## Complete IDOR Testing Workflow

### Scenario: Test if Alice can access Bob's resources

#### Step 1: Static Analysis (SESSION mode)

```bash
./scripts/idor_interface.py

# Switch to SESSION mode
> m

# Create session
> 1
Session index: 1

# Add Burp XML exports to sessions/session_1/input/

# Run analyzer
> 4
[Select history.xml and sitemap.xml]

# Review candidates in output/idor_candidates.csv
```

#### Step 2: Dynamic Testing (UI_AUTOMATION mode)

```bash
# Switch to UI_AUTOMATION mode
> m
> m

# Configure users
> 1
User ID: alice
User ID: bob

# From another terminal, record sequences
cd scripts/
npm install
npm run test:record

# Back in interface, browse and save
> 3
[Select sequence files]
Which user owns this? alice

# Execute as different user
> 4
Select sequence: 1 (alice's sequence)
Execute as user: bob

# Check if Bob can access Alice's resources
```

#### Step 3: Compare Results

```bash
# View saved box
> s

# Open recordings in Codium for comparison
> c
[Select alice's recording]

# Open in another window
> c
[Select bob's recording]

# Diff in Codium to find IDOR vulnerabilities
```

## Directory Structure

```
idor-analysis-template/
├── .project_root              # Project root marker
├── sessions/                  # SESSION mode data
│   └── session_1/
│       ├── input/
│       │   ├── history_1.xml
│       │   └── sitemap_1.xml
│       └── output/
│           ├── idor_candidates.csv
│           └── permutations_*.txt
│
├── ui-automation/            # UI_AUTOMATION mode data
│   ├── sequences.json        # User-agnostic sequences
│   ├── recordings/           # Per-user recordings
│   ├── users.json           # Configured users
│   └── README.md
│
├── scripts/
│   ├── idor_interface.py     # Main interface (3 modes)
│   ├── playwright-session-manager.js
│   ├── playwright-examples.js
│   └── package.json
│
└── src/                      # IDOR analysis tools
    ├── idor_analyzer.py
    ├── idor_permutator.py
    └── ...
```

## Quick Start Examples

### Example 1: PROJECT Mode

```bash
./scripts/idor_interface.py

# Already in PROJECT mode
> 3                          # Browse tree
[Select files to save]

> s                          # Show saved box
[View saved paths]

> c                          # Open in Codium
[Edit files]
```

### Example 2: SESSION Mode

```bash
./scripts/idor_interface.py

> m                          # Switch to SESSION mode
> 1                          # Create session
Session index: 2

# Add XML files to sessions/session_2/input/

> 4                          # Run IDOR analyzer
> 6                          # Run permutator
Message ID: 42
```

### Example 3: UI_AUTOMATION Mode

```bash
./scripts/idor_interface.py

> m                          # Switch to SESSION
> m                          # Switch to UI_AUTOMATION

> 1                          # Configure users
User ID: alice
[Ctrl+C to finish]

> 2                          # List sequences
[View recorded sequences]

> 3                          # Browse tree
[Save sequence files with user context]

> s                          # Show saved box
[See user-grouped entries]

> 4                          # Execute sequence
[Select sequence and user]

> c                          # Open in Codium
[View/edit sequence files]
```

## Integration Benefits

### 1. Unified Interface

All workflows accessible from one menu:
- Static analysis (Burp XML)
- Dynamic testing (Playwright)
- Project management (files/docs)

### 2. User Context Tracking

UI_AUTOMATION mode preserves user ownership:
- Know which user recorded which sequence
- Execute sequences as different users
- Compare multi-user recordings

### 3. Flexible Navigation

Toggle between modes instantly:
```bash
> m    # PROJECT → SESSION
> m    # SESSION → UI_AUTOMATION
> m    # UI_AUTOMATION → PROJECT
```

### 4. Consistent Operations

Same commands work across modes:
- `3` = Browse tree & save path
- `c` = Open in Codium
- `s` = Show saved box
- `m` = Toggle mode

### 5. Complementary Workflows

**Static + Dynamic:**
1. Burp XML analysis finds candidates → SESSION mode
2. Playwright tests candidates live → UI_AUTOMATION mode
3. Compare results → PROJECT mode (docs)

## Tips

### Tip 1: Mode-Specific Operations

Some operations only work in specific modes:
- `Run IDOR analyzer` → SESSION only
- `Execute saved sequence` → UI_AUTOMATION only
- Menu adapts to current mode

### Tip 2: Saved Box Per Mode

Each mode has its own saved box:
- Switch modes = switch saved boxes
- Context preserved when returning to mode

### Tip 3: User Context Matters

In UI_AUTOMATION mode, always specify user:
```bash
> 3
Which user owns this? alice    # Track ownership
```

### Tip 4: Cross-Mode Workflow

Combine modes for complete testing:

```
SESSION mode: Identify IDOR candidates
     ↓
UI_AUTOMATION mode: Record Alice accessing resource
     ↓
UI_AUTOMATION mode: Replay as Bob
     ↓
PROJECT mode: Document findings
```

## Advanced Usage

### Automated IDOR Testing

```bash
# 1. SESSION mode: Batch analyze multiple captures
for xml in captures/*.xml; do
    # Import via interface
done

# 2. UI_AUTOMATION mode: Automated replay
cd scripts/
npm run test:examples

# 3. Compare results programmatically
diff -u recordings/alice-* recordings/bob-*
```

### Custom Sequences

```bash
# 1. UI_AUTOMATION mode: Configure users
> 1
User ID: admin
User ID: user

# 2. Record custom sequence (Node.js)
cd scripts/
npx playwright test my-custom-test.spec.js

# 3. Back to interface: Execute
> 4
Execute as: user
[Test if user can access admin resources]
```

### Integration with CI/CD

```bash
# Run static analysis
./scripts/idor_interface.py < session_commands.txt

# Run dynamic tests
cd scripts/
npm run test:idor-suite

# Generate reports
python3 src/idor_analyzer.py history.xml > report.txt
```

## Troubleshooting

### "Invalid option" in UI_AUTOMATION mode

Some operations don't exist in all modes:
- Check menu for available options
- Mode-specific operations are numbered 1-6

### "User not configured"

In UI_AUTOMATION mode:
```bash
> 1                    # Configure users first
User ID: alice
User ID: bob
```

### "Empty saved box"

Each mode has separate saved box:
- Use `3` (Browse tree) to add items
- Use `s` to verify items were saved
- Switch modes to see other saved boxes

### Playwright not installed

```bash
cd scripts/
npm install
npx playwright install chromium
```

## See Also

- `src/idor_analyzer.py` - Static analysis tool
- `src/idor_permutator.py` - Mutation generator
- `scripts/playwright-session-manager.js` - Dynamic testing core
- `scripts/PLAYWRIGHT-README.md` - Full Playwright docs
- `ui-automation/README.md` - UI automation specifics
- `docs/workflow.md` - Analysis methodology
