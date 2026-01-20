# UI Automation Directory

This directory stores Playwright multi-user session recordings managed through the IDOR interface.

## Integration with idor_interface.py

The main interface (`scripts/idor_interface.py`) now has three navigation modes:

- **PROJECT** - Project root operations
- **SESSION** - IDOR analysis sessions (XML/Burp data)
- **UI_AUTOMATION** - Playwright multi-user testing

## Navigation

```bash
./scripts/idor_interface.py

# Press 'm' to cycle through modes:
# project → session → ui_automation → project → ...
```

## UI Automation Mode Menu

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

## Directory Structure

```
ui-automation/
├── sequences.json       # Sequence definitions (user-agnostic workflows)
├── recordings/          # Full execution recordings per user
│   ├── seq-123-alice-*.json
│   └── seq-123-bob-*.json
└── users.json          # Configured users (alice, bob, etc.)
```

## Saved Box with User Context

The saved box in UI_AUTOMATION mode tracks which user created/owns each entry:

```
=== UI AUTOMATION SAVED BOX ===

----User alice:
  [1] /home/user/project/ui-automation/sequences.json
  [2] /home/user/project/ui-automation/recordings/seq-123-alice-456.json

----User bob:
  [1] /home/user/project/ui-automation/recordings/seq-123-bob-789.json
```

## Workflow

### 1. Configure Users

```
Mode: UI_AUTOMATION
> 1

User ID: alice
✓ User alice configured

User ID: bob
✓ User bob configured
```

### 2. Create Sequences (via Playwright scripts)

From `scripts/` directory:

```bash
cd scripts/
npm install
npm run test:demo
```

This creates sequences in `ui-automation/sequences.json`.

### 3. Browse and Save Paths

```
Mode: UI_AUTOMATION
> 3

[1] ui-automation
[2] ui-automation/sequences.json
[3] ui-automation/recordings
[4] ui-automation/recordings/seq-123-alice-456.json

Enter number to save: 4
Which user owns this? alice

✓ Saved: recordings/seq-123-alice-456.json (User: alice)
```

### 4. View Saved Box

```
> s

=== UI AUTOMATION SAVED BOX ===

----User alice:
  [1] recordings/seq-123-alice-456.json

----User bob:
  [1] recordings/seq-123-bob-789.json
```

### 5. Open in Codium

```
> c

[1] User alice: recordings/seq-123-alice-456.json
[2] User bob: recordings/seq-123-bob-789.json

Select item to open: 1
✓ Opened in Codium
```

### 6. Execute Sequence

```
> 4

[1] User alice: recordings/seq-123-alice-456.json
[2] User bob: recordings/seq-123-bob-789.json

Select sequence to execute: 1
Original user: alice
Execute as user (blank = original): bob

[*] Executing as bob...
```

## Integration with Playwright Scripts

The Playwright session manager in `scripts/` creates files that are managed through this interface:

1. **Record sequences** using Playwright scripts
2. **Browse and save** using idor_interface.py (mode: ui_automation)
3. **Execute with different users** for IDOR testing
4. **Compare recordings** to detect authorization issues

## Use Cases

### IDOR Testing

1. Record Alice accessing resource: `seq-project-access`
2. Execute same sequence as Bob
3. Compare recordings:
   - Both 200 OK → IDOR vulnerability
   - Alice 200, Bob 403 → Proper authorization

### Multi-User Workflows

1. Configure multiple users (alice, bob, admin)
2. Record workflows for each user
3. Track in saved box by user
4. Replay and compare behaviors

## File Formats

### sequences.json

```json
{
  "sequences": [
    {
      "id": "seq-123",
      "name": "Project Access",
      "description": "Access project documents",
      "created": "2026-01-19T10:00:00Z",
      "recorded_by": "alice",
      "actions": [
        {
          "step": "navigate to projects",
          "t_start_sec": "2.345",
          "requests": [...]
        }
      ]
    }
  ]
}
```

### users.json

```json
{
  "users": ["alice", "bob", "admin"]
}
```

### Recording Files

```json
{
  "sequenceId": "seq-123",
  "user": "alice",
  "timestamp": "2026-01-19T10:30:00Z",
  "buckets": [
    {
      "action": "navigate to projects",
      "t_start_sec": "2.345",
      "requests": [
        {
          "method": "GET",
          "url": "https://app.com/api/projects",
          "status": 200,
          "responseBody": "..."
        }
      ]
    }
  ]
}
```

## Tips

- **User context matters**: Always specify which user when saving paths
- **Compare recordings**: Use Codium to diff alice vs bob recordings
- **Sequence reuse**: Record once, replay with any user
- **Project root**: All paths respect the project root structure

## See Also

- `scripts/PLAYWRIGHT-README.md` - Full Playwright documentation
- `scripts/QUICKSTART.md` - Quick start guide
- `scripts/playwright-session-manager.js` - Core implementation
