# CLI Architecture: Separated Concerns

This project now has **two distinct CLIs** for different purposes, reflecting a clean separation of concerns.

---

## 1. Playwright Recorder (Node.js)

**Location**: `scripts/playwright-session-manager.js`

**Purpose**: Browser automation, HTTP capture, multi-user session recording

**Run with**:
```bash
cd scripts
npm run cli
```

### Features

- **User Management**: Configure users with credentials and browser profiles
- **Browser Profile Modes**:
  - Managed: Playwright-owned profiles (automatic)
  - Trusted: Pre-bootstrapped profiles for Cloudflare
- **Recording**: Capture user workflows with action boundaries
- **Replay**: Re-execute sequences with different users
- **Test Generation**: Auto-generate Playwright tests from recordings
- **Bootstrap Helper**: One-time Cloudflare trust establishment

### Output Format

Recordings are saved as **JSON** with this structure:
```json
{
  "user": "alice",
  "sequenceId": "seq-123",
  "timestamp": "2024-01-22T...",
  "buckets": [
    {
      "action": "Login to application",
      "t_start_sec": 0.234,
      "requests": [
        {
          "method": "POST",
          "url": "https://example.com/api/login",
          "headers": {...},
          "postData": "...",
          "status": 200,
          "responseHeaders": {...},
          "responseBody": "..."
        }
      ]
    }
  ],
  "validation": {
    "totalActions": 5,
    "totalRequests": 23,
    "validated": true
  }
}
```

### Key Design Decisions

1. **Action-Aware Capture**: HTTP traffic is partitioned by user-defined actions
2. **Per-User Isolation**: Each user has independent sessions and profiles
3. **Validation**: Fails loudly if recordings capture zero requests (Cloudflare detection)
4. **Test Generation**: Can generate single-user or multi-user IDOR tests

---

## 2. IDOR Analyzer (Python)

**Location**: `scripts/idor_interface.py`

**Purpose**: Security analysis, IDOR detection, vulnerability assessment

**Run with**:
```bash
cd scripts
python3 idor_interface.py
```

### Features

- **Session Management**: Organize analysis projects
- **Playwright Integration**: Direct JSON input (no XML conversion)
- **Action Selection**: Analyze specific workflow segments
- **IDOR Detection**: Pattern-based vulnerability analysis
- **Reports**: Detailed findings with severity levels

### Input Formats

**Primary (New)**: Playwright JSON (lossless)
- Direct consumption of Playwright recordings
- No intermediate conversion
- Full HTTP request/response data preserved

**Legacy**: Burp XML
- Still supported for traditional workflows
- Sitemap + History XML

### Analysis Output

```
=== IDOR ANALYSIS REPORT ===

User: alice
Actions: 5
Requests: 23

FINDINGS SUMMARY:
High Severity: 3
Medium Severity: 2

HIGH SEVERITY FINDINGS:

[1] GET https://example.com/api/users/12345
    Type: numeric_id_in_path
    Description: URL contains numeric IDs that may be enumerable

[2] POST https://example.com/api/profile/update
    Type: id_in_request_body
    Description: Request body contains IDs that may reference other users
```

---

## Why This Separation?

### Before (Single Monolithic CLI)

**Problems**:
- Mode switching (`NAV_MODE`) was confusing
- Mixed concerns (automation + security analysis)
- Different user bases (QA engineers vs security testers)
- Language mismatch (Node.js vs Python in one interface)

### After (Two Specialized CLIs)

**Benefits**:
- **Clear purpose**: Each CLI does one thing well
- **Technology fit**: Node.js for Playwright, Python for analysis
- **Independent evolution**: Can improve each without breaking the other
- **Composable**: Output of Recorder → Input of Analyzer

---

## Workflow Integration

### End-to-End IDOR Testing

```bash
# 1. Record user sessions (Playwright CLI)
cd scripts
npm run cli
# → Configure Users (alice, bob)
# → Record New Sequence (alice's workflow)
# → Generate Test from Recording (multi-user)

# 2. Run generated test
npx playwright test

# 3. Analyze recordings (IDOR CLI)
python3 idor_interface.py
# → Switch to UI Automation mode (m)
# → Analyze recording for IDORs (5)
# → Select alice's recording
# → Get IDOR report
```

### Data Flow

```
User Workflow
    ↓
Playwright Recorder (capture)
    ↓
JSON Recording (saved-sequences/recordings/)
    ↓
Test Generator (optional)
    ↓
Multi-User Replay
    ↓
IDOR Analyzer (analyze)
    ↓
Security Report
```

---

## File Organization

```
scripts/
├── playwright-session-manager.js    # Recorder CLI
├── idor_interface.py                # Analyzer CLI
├── saved-sequences/
│   └── recordings/                  # JSON recordings
├── auth-sessions/
│   ├── users.json                   # User configs
│   └── browser-profiles/            # Persistent contexts
└── package.json                     # Node.js deps

src/
├── playwright_json_parser.py        # JSON parsing lib
├── idor_analyzer_json.py            # New JSON-based analyzer
├── idor_analyzer.py                 # Legacy XML analyzer
└── ...

sessions/
└── playwright_alice_123/            # Analysis sessions
    ├── input/
    │   └── recording.json          # Filtered recording
    └── output/
        └── idor_playwright_analysis.txt
```

---

## Migration Guide

### From Old Workflow (XML-based)

**Before**:
```python
# Convert Playwright → Burp XML → Analyzer
convert_playwright_to_burp_xml(buckets, history_xml)
run_analyzer(history_xml, sitemap_xml)
```

**After**:
```python
# Direct Playwright JSON → Analyzer (lossless)
from playwright_json_parser import PlaywrightRecording
recording = PlaywrightRecording('recording.json')
analysis = analyze_recording(recording)
```

**Benefits**:
- No conversion overhead
- No data loss in transformation
- Faster analysis
- Better error messages

### From Single CLI to Dual CLI

**Before**:
```bash
python3 idor_interface.py
# Toggle mode (m) → ui_automation
# Record sequence (ambiguous which tool)
```

**After**:
```bash
# Recording: Use Node.js CLI
npm run cli

# Analysis: Use Python CLI
python3 idor_interface.py
```

---

## Design Principles

### 1. Separation of Concerns
- **Recorder**: Knows about browsers, actions, sessions
- **Analyzer**: Knows about security, patterns, IDORs

### 2. Lossless Data Flow
- No XML conversion step
- Full HTTP context preserved
- Action annotations maintained

### 3. Explicit Over Implicit
- Clear CLI boundaries
- No hidden mode switching
- Obvious data handoff points

### 4. Fail Loudly
- Recording validation at save time
- Missing files cause errors (not silent failures)
- Clear error messages with solutions

### 5. User-Centric Design
- Each CLI serves a specific persona
- Minimal mode switching
- Enumerated menus throughout

---

## Future Enhancements

### Recorder CLI
- [ ] Live recording with visual feedback
- [ ] Diff view for sequence comparison
- [ ] Template-based test generation

### Analyzer CLI
- [ ] Automated multi-user comparison
- [ ] Machine learning-based IDOR detection
- [ ] Integration with Burp via JSON export

### Integration
- [ ] Automated workflow orchestration
- [ ] CI/CD pipeline integration
- [ ] Report aggregation across sessions

---

## Technical Debt Removed

✅ **Removed redundant session management**
- Eliminated duplicate cookie/localStorage storage
- Persistent contexts are now the single source of truth

✅ **Removed XML conversion layer**
- Direct JSON input to analyzer
- Lossless data transformation

✅ **Removed mode confusion**
- Clear separation: Recorder vs Analyzer
- No more `NAV_MODE` switching

✅ **Added recording validation**
- Fails loudly on empty recordings
- Prevents silent Cloudflare blocks

✅ **Added test generation**
- Auto-generate replay tests
- Multi-user IDOR testing support

---

## Summary

| Aspect | Playwright Recorder | IDOR Analyzer |
|--------|-------------------|---------------|
| **Language** | Node.js | Python |
| **Purpose** | Capture workflows | Find vulnerabilities |
| **Input** | User actions | JSON recordings |
| **Output** | JSON recordings | Security reports |
| **Users** | QA, automation engineers | Security testers, bug hunters |
| **Data** | HTTP traffic + actions | Patterns + findings |

**The key insight**: These are two different tools that happen to work together, not one tool with two modes.
