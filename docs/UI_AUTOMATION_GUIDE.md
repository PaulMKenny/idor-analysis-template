# UI Automation for IDOR Testing - Complete Guide

## Overview

The UI automation script provides **iterative, interactive browser automation** with full HTTP capture for IDOR analysis. No hardcoded actions - build test sequences dynamically in a REPL interface.

## Key Features

✅ **Interactive REPL** - Add actions iteratively, not hardcoded
✅ **Full HTTP Capture** - Burp XML format compatible with idor_analyzer.py
✅ **Action Bookmarks** - Track action boundaries tied to HTTP requests
✅ **Save/Replay** - Record sequences and replay across multiple users
✅ **Multi-User Testing** - Compare same actions with different privilege levels
✅ **Session Integration** - Works seamlessly with existing session_N directory structure

---

## Quick Start

### 1. Setup Browser Profiles

Create persistent browser profiles for different user roles:

```bash
# Create profile directories
mkdir -p ~/pw-profiles/admin
mkdir -p ~/pw-profiles/user_a
mkdir -p ~/pw-profiles/user_b

# Launch browsers to log in and save credentials
# These will persist across sessions
playwright open --user-data-dir ~/pw-profiles/admin https://target.com/login
playwright open --user-data-dir ~/pw-profiles/user_a https://target.com/login
playwright open --user-data-dir ~/pw-profiles/user_b https://target.com/login
```

### 2. Record Baseline Actions (Admin User)

```bash
python scripts/ui_automation.py --profile ~/pw-profiles/admin --session 1
```

**Interactive session:**

```
[UI-Auto] > goto https://target.com/dashboard
✓ Navigated to https://target.com/dashboard

[UI-Auto] > mark Open dashboard
[ACTION 1] Open dashboard

[UI-Auto] > click text=Users
✓ Clicked text=Users

[UI-Auto] > mark Navigate to users list
[ACTION 2] Navigate to users list

[UI-Auto] > click text=John Doe
✓ Clicked text=John Doe

[UI-Auto] > mark View user detail
[ACTION 3] View user detail

[UI-Auto] > click button:has-text('Edit')
✓ Clicked button:has-text('Edit')

[UI-Auto] > mark Edit user form
[ACTION 4] Edit user form

[UI-Auto] > save baseline_actions.json
✓ Saved 4 actions to baseline_actions.json

[UI-Auto] > quit
```

**Output:**
- `sessions/session_1/input/history_1.xml` - Full HTTP capture
- `sessions/session_1/input/actions_1.json` - Action bookmarks
- `baseline_actions.json` - Replayable action sequence

### 3. Replay with Multiple Users

Create `profiles.json`:

```json
{
  "admin": "/home/user/pw-profiles/admin",
  "user_a": "/home/user/pw-profiles/user_a",
  "user_b": "/home/user/pw-profiles/user_b"
}
```

Run multi-user test:

```bash
python scripts/multi_user_idor_test.py baseline_actions.json --profiles profiles.json
```

**Output:**
- `sessions/session_100/` - Admin replay
- `sessions/session_101/` - User A replay
- `sessions/session_102/` - User B replay
- `idor_comparison.txt` - Differential analysis report

### 4. Analyze Results

The multi-user script automatically runs `idor_analyzer.py` on each session. Check:

```bash
# View admin analysis
cat sessions/session_100/output/history_100_idor_triage.txt

# View user_a analysis
cat sessions/session_101/output/history_101_idor_triage.txt

# View comparison report
cat idor_comparison.txt
```

**Look for:**
- IDs accessible by multiple users (potential IDOR)
- High-scoring Tier 1 candidates
- Cross-user response differences

---

## Detailed Command Reference

### Interactive Commands

| Command | Description | Example |
|---------|-------------|---------|
| `goto <url>` | Navigate to URL | `goto https://target.com/users` |
| `click <selector>` | Click element | `click text=Edit` or `click button#save` |
| `fill <selector>\|<value>` | Fill input field | `fill input[name=email]\|test@example.com` |
| `press <key>` | Press keyboard key | `press Enter` |
| `wait <ms>` | Wait milliseconds | `wait 2000` |
| `wait_for <selector>` | Wait for element | `wait_for .loading-complete` |
| `mark <description>` | Mark action boundary | `mark User list loaded` |
| `save <filename>` | Save action sequence | `save test_sequence.json` |
| `history` | Show action summary | `history` |
| `quit` | Exit session | `quit` |

### Playwright Selectors

The `click` and `fill` commands support Playwright's flexible selector syntax:

```bash
# Text content
click text=Sign In
click text=/log.*out/i

# CSS selectors
click button#submit
click .nav-item:has-text('Users')

# XPath
click xpath=//button[@type='submit']

# Chaining
click nav >> text=Users
click article:has-text('John') >> button.edit
```

**Documentation:** https://playwright.dev/docs/selectors

---

## Advanced Workflows

### Scenario 1: Testing Object Access Control

**Goal:** Verify user_a cannot access user_b's profile.

```bash
# 1. Record admin accessing both profiles
python scripts/ui_automation.py --profile ~/pw-profiles/admin --session 10

[UI-Auto] > goto https://target.com/users/123
[UI-Auto] > mark Access user 123
[UI-Auto] > goto https://target.com/users/456
[UI-Auto] > mark Access user 456
[UI-Auto] > save multi_user_access.json
[UI-Auto] > quit

# 2. Replay as user_a (ID 123)
python scripts/ui_automation.py --profile ~/pw-profiles/user_a --session 11 --replay multi_user_access.json

# 3. Replay as user_b (ID 456)
python scripts/ui_automation.py --profile ~/pw-profiles/user_b --session 12 --replay multi_user_access.json

# 4. Compare responses
diff sessions/session_11/output/history_11_idor_candidates.csv \
     sessions/session_12/output/history_12_idor_candidates.csv
```

**Expected:** user_a should NOT successfully access /users/456.

### Scenario 2: Testing GraphQL Mutations

```bash
[UI-Auto] > goto https://target.com/graphql-playground
[UI-Auto] > mark GraphQL interface loaded

# Execute mutation in UI
[UI-Auto] > click button:has-text('Run')
[UI-Auto] > mark Execute updateUser mutation

# HTTP capture will include GraphQL request with variables:
# POST /graphql
# {"query": "mutation($id: ID!) { updateUser(id: $id) {...} }", "variables": {"id": "123"}}
```

The analyzer will:
- Extract `id: "123"` from GraphQL variables (high signal)
- Mark as mutation endpoint
- Score higher for IDOR testing

### Scenario 3: Token Binding Analysis

```bash
# Capture requests with different Authorization tokens
python scripts/ui_automation.py --profile ~/pw-profiles/user_a --session 20

[UI-Auto] > goto https://target.com/api/account
[UI-Auto] > mark Fetch account with user_a token
[UI-Auto] > quit

# Switch profiles (different JWT)
python scripts/ui_automation.py --profile ~/pw-profiles/user_b --session 21 --replay session_20_actions.json
```

The analyzer will:
- Detect JWT in Authorization header
- Check if response IDs are bound to token claims
- Flag token-bound vs token-independent IDs

---

## Integration with Existing Tools

### Workflow Diagram

```
┌─────────────────────────────────────────────────────┐
│  ui_automation.py (REPL or Replay)                 │
│  ↓ Captures HTTP in Burp XML                       │
└──────────────────┬──────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────┐
│  session_N/input/history_N.xml                      │
│  (Full HTTP request/response pairs)                 │
└──────────────────┬───────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────┐
│  idor_analyzer.py                                   │
│  ↓ Extracts IDs, scores candidates, tiering         │
└──────────────────┬───────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────┐
│  session_N/output/                                  │
│  ├─ history_N_idor_candidates.csv                   │
│  ├─ history_N_idor_triage.txt                       │
│  └─ history_N_permutator_index.json                 │
└──────────────────┬───────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────┐
│  idor_permutator.py                                 │
│  ↓ Generates mutation test cases                    │
└──────────────────┬───────────────────────────────────┘
                   │
                   ↓
┌──────────────────────────────────────────────────────┐
│  Manual testing with Burp/curl/etc.                 │
│  (Use generated permutations)                       │
└──────────────────────────────────────────────────────┘
```

### File Format Compatibility

The UI automation script produces **exact** Burp XML format:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<items>
  <item>
    <request base64="true">UE9TVCAva....</request>
    <response base64="true">SFRUUC8xL...</response>
  </item>
  <!-- More items -->
</items>
```

This is **100% compatible** with:
- `idor_analyzer.py` (primary consumer)
- `raw_http_dump.py` (message inspector)
- `idor_permutator.py` (via permutator_index.json)
- Burp Suite (can import/export)

---

## Troubleshooting

### Issue: Selector not found

```
❌ Error: Timeout 30000ms exceeded waiting for selector "text=Users"
```

**Solutions:**
1. Use `wait_for <selector>` before clicking
2. Try alternative selectors: `button:has-text('Users')` or `.user-link`
3. Check if element is in iframe: `click iframe >> text=Users`

### Issue: Request not captured

```
[CAPTURE] Flushed 0 HTTP pairs to ...
```

**Solutions:**
1. Ensure `mark` is called AFTER navigation/clicks
2. Add `wait <ms>` for async requests to complete
3. Check if requests are WebSocket (not captured by route handler)

### Issue: Analysis shows no candidates

```
Total unique IDs: 0
```

**Solutions:**
1. Verify HTTP capture has request bodies: `cat sessions/session_N/input/history_N.xml | base64 -d | grep POST`
2. Check if responses contain IDs: use `raw_http_dump.py`
3. Ensure actions triggered actual API calls (not just UI changes)

### Issue: Multi-user test profiles conflict

```
❌ user_a failed: Browser already running
```

**Solutions:**
1. Each profile must have unique `user_data_dir`
2. Close all browser instances before replay
3. Use `--visible` flag to debug profile issues

---

## Best Practices

### 1. Mark Strategic Boundaries

```bash
# ✅ Good: Mark after meaningful state changes
mark "User list loaded"
mark "Edit form opened"
mark "Profile update submitted"

# ❌ Bad: Too granular
mark "Clicked button"
mark "Waited 1 second"
```

### 2. Wait for Async Operations

```bash
# ✅ Good: Ensure requests complete
click text=Save
wait 2000                    # Wait for POST request
mark "Profile saved"

# ❌ Bad: Mark immediately
click text=Save
mark "Profile saved"         # Might miss the POST request
```

### 3. Use Descriptive Action Sequences

```json
// ✅ Good: Self-documenting
{
  "actions": [
    ["goto", "https://target.com/users"],
    ["click", "text=John Doe"],
    ["click", "button:has-text('Edit')"]
  ]
}

// ❌ Bad: Cryptic selectors
{
  "actions": [
    ["goto", "https://target.com/users"],
    ["click", "#a123"],
    ["click", ".btn-primary"]
  ]
}
```

### 4. Test with Realistic Data

- Use real user IDs, not admin test accounts
- Include edge cases (deleted users, archived resources)
- Test with expired/invalid tokens

---

## Security Considerations

### Authorization Testing Best Practices

1. **Always test with legitimate accounts** - Never use stolen credentials
2. **Test on authorized targets only** - Get explicit permission
3. **Document findings responsibly** - Follow disclosure policies
4. **Don't test destructive operations** - Avoid DELETE mutations in production

### Profile Management

- **Never commit profile directories** - Add to `.gitignore`
- **Use separate profiles per environment** - dev/staging/prod
- **Rotate credentials regularly** - Update profiles when passwords change

---

## Extending the Script

### Custom Actions

Add new commands to `ui_automation.py`:

```python
elif action == "screenshot":
    filename = args or f"screenshot_{int(time.time())}.png"
    page.screenshot(path=filename)
    print(f"✓ Screenshot saved to {filename}")

elif action == "eval":
    result = page.evaluate(args)
    print(f"✓ Result: {result}")
```

### Custom Capture Filters

Filter captured requests by domain/pattern:

```python
def _route_handler(self, route: Route, request: Request):
    # Skip third-party domains
    if "analytics.com" in request.url or "cdn.jsdelivr.net" in request.url:
        return route.continue_()

    # Only capture API calls
    if "/api/" not in request.url:
        return route.continue_()

    # Rest of capture logic...
```

### Integration with CI/CD

```yaml
# .github/workflows/idor-test.yml
name: IDOR Regression Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  idor-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4

      - name: Install dependencies
        run: |
          pip install playwright
          playwright install chromium

      - name: Run IDOR tests
        run: |
          python scripts/ui_automation.py \
            --replay baseline_actions.json \
            --profile ${{ secrets.TEST_PROFILE_PATH }} \
            --session ${{ github.run_number }} \
            --headless

      - name: Analyze results
        run: |
          cd sessions/session_${{ github.run_number }}/output
          python ../../../src/idor_analyzer.py ../input/history_*.xml

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: idor-analysis
          path: sessions/session_*/output/*_idor_*.csv
```

---

## FAQ

**Q: Why not just use Burp proxy?**
A: Burp is great for manual testing, but UI automation with replay across multiple users enables **systematic IDOR regression testing**.

**Q: Can I use this with mobile apps?**
A: Not directly. For mobile, use mitmproxy with similar action bookmarking:
```python
# mitmproxy addon
class ActionLogger:
    def request(self, flow):
        flow.metadata["action_id"] = current_action_id
```

**Q: How do I handle CAPTCHA/2FA?**
A: Use persistent browser profiles with saved sessions. Log in manually once, then profiles retain cookies.

**Q: Can I parallelize multi-user tests?**
A: Yes! Modify `multi_user_idor_test.py` to use `multiprocessing`:
```python
from multiprocessing import Pool

with Pool(processes=len(profiles)) as pool:
    pool.starmap(run_profile, profile_tasks)
```

**Q: What about WebSocket traffic?**
A: Current implementation doesn't capture WebSocket. For WS, use browser DevTools protocol:
```python
context.on("websocket", lambda ws: ws.on("framereceived", capture_frame))
```

---

## Next Steps

1. ✅ **Setup profiles** - Create browser profiles for test users
2. ✅ **Record baseline** - Capture admin workflow interactively
3. ✅ **Replay multi-user** - Test with lower-privilege accounts
4. ✅ **Analyze** - Review IDOR candidates and comparison report
5. ⏭️ **Generate mutations** - Use `idor_permutator.py` on high-scoring candidates
6. ⏭️ **Manual verification** - Test mutations with Burp/curl
7. ⏭️ **Report findings** - Document confirmed IDORs

---

## Support

For issues or questions:
- Check troubleshooting section above
- Review existing session outputs for examples
- Consult idor_analyzer.py documentation for scoring details

**Happy IDOR hunting! 🔍🔐**
