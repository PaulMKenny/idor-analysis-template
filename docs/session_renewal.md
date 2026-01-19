# Session Token Renewal for IDOR Testing

## Overview

The diff module now supports **automated session token renewal** using Playwright browser automation. This solves the critical problem of expired tokens when testing IDOR vulnerabilities hours or days after capturing traffic.

## The Problem

Previously, when comparing User A vs User B requests:
1. User B's tokens (cookies, auth headers) were extracted from XML at **export time**
2. Generated curl commands had **hardcoded stale tokens**
3. Running the curl command hours/days later would **fail with 401 Unauthorized**
4. Manual token refresh was tedious and error-prone

## The Solution

Three modes for handling session tokens:

### 1. Playwright Automation (Recommended)
- Automatically logs in as User B using browser automation
- Extracts fresh cookies and auth headers
- Runs headless or with visible browser
- One-time setup per session

### 2. Manual Token Entry
- Prompts you to paste fresh tokens from Burp/Browser DevTools
- Useful as fallback or for complex auth flows

### 3. Skip (Legacy Behavior)
- Uses stale tokens from XML
- Only works if tokens haven't expired yet

## Setup

### Install Dependencies

```bash
# Install Playwright
pip install playwright

# Install browser
playwright install chromium
```

### Configure Login Flow for User B Session

1. Run `idor_interface.py` in **Session Mode**
2. Select option **7) Configure login flow**
3. Select the User B session
4. Follow the interactive wizard:
   - Enter login URL
   - Provide CSS selectors for username/password fields
   - Enter User B credentials
   - Configure success indicator (URL change or element appearance)
   - Optionally extract JWT from localStorage

**Example Configuration:**

```
Login page URL: https://example.com/login
Username field selector: #username
Password field selector: #password
Submit button selector: button[type='submit']
Username: userb@example.com
Password: userb_password123
Success indicator: URL contains '/dashboard'
```

This creates `sessions/session_2/login_config.json`.

## Usage Workflow

### Running User A vs User B Diff with Fresh Tokens

1. Run `idor_interface.py`
2. Toggle to **Session Mode** (press `m`)
3. Select option **8) User A vs User B diff + replay**
4. Select User A session and history XML
5. Select User B session and history XML
6. Enter message ID from User A to test
7. **Choose token refresh mode:**
   - `1` for Playwright automation
   - `2` for manual entry
   - `3` to skip (use stale tokens)
8. If using Playwright:
   - Choose headless (Y) or visible browser (n)
   - Browser will launch, login automatically, and extract tokens
9. Review the generated curl command in `sessions/session_2/output/replay_diff_msg_{id}.txt`
10. Execute the curl command to test for IDOR

## Configuration File Format

Location: `sessions/{session_name}/login_config.json`

```json
{
  "login_url": "https://example.com/login",
  "selectors": {
    "username": "#username",
    "password": "#password",
    "submit": "button[type='submit']"
  },
  "credentials": {
    "username": "userb@example.com",
    "password": "userb_password123"
  },
  "success_indicator": {
    "type": "url_contains",
    "value": "/dashboard"
  },
  "auth_header_extraction": {
    "storage_key": "auth_token",
    "prefix": "Bearer"
  }
}
```

### Success Indicator Types

**URL Contains:**
```json
"success_indicator": {
  "type": "url_contains",
  "value": "/dashboard"
}
```

**Element Appears:**
```json
"success_indicator": {
  "type": "element",
  "value": ".user-menu"
}
```

**None (wait 3 seconds):**
```json
"success_indicator": {}
```

## Finding CSS Selectors

### Chrome DevTools
1. Right-click element → Inspect
2. In Elements panel, right-click the element
3. Copy → Copy selector

### Firefox DevTools
1. Right-click element → Inspect
2. In Inspector panel, right-click the element
3. Copy → CSS Selector

### Common Patterns
- By ID: `#username`
- By name: `input[name="username"]`
- By type: `button[type="submit"]`
- By class: `.login-button`

## Security Considerations

### Warning: Credentials Stored in Plaintext

The `login_config.json` file stores credentials in **plaintext**. This is a deliberate tradeoff for automation.

**Best Practices:**
- Only use for test accounts
- Never commit `login_config.json` to git
- Consider using environment variables (future enhancement)
- Use separate test credentials, not production

### Git Ignore

Add to `.gitignore`:
```
sessions/*/login_config.json
sessions/*/output/
```

## Troubleshooting

### Playwright Not Found
```bash
pip install playwright
playwright install chromium
```

### Login Fails
- Run with visible browser (press `n` when asked about headless)
- Check if selectors are correct
- Check if success indicator is accurate
- Check if MFA/captcha is blocking automation

### Tokens Still Expire Quickly
- Check if app uses short-lived tokens (< 5 minutes)
- Consider running token renewal immediately before executing curl
- May need to implement continuous token refresh (future enhancement)

### Authorization Header Not Extracted
- Verify the token is actually stored in localStorage/sessionStorage
- Check the storage key name in browser DevTools
- Some apps use httpOnly cookies (can't extract from JS)

## Comparison to Autorize

| Feature | Autorize | This Tool (with Playwright) |
|---------|----------|------------------------------|
| Real-time testing | ✅ | ❌ |
| Token management | ✅ Automatic | ✅ Semi-automatic |
| Offline analysis | ❌ | ✅ |
| Curl generation | ❌ | ✅ |
| Scriptable | ❌ | ✅ |
| CI/CD integration | ❌ | ✅ (with config) |
| Setup complexity | Low | Medium |

## Future Enhancements

Potential improvements:
- Environment variable support for credentials
- Token caching with expiry tracking
- Multi-factor authentication handling
- Integration with password managers
- Burp Suite extension API integration
- Automatic token refresh on 401 errors

## Example Output

```bash
$ cat sessions/session_2/output/replay_diff_msg_42.txt

=== CURL ===
curl -X POST 'https://api.example.com/users/1234/profile' \
  -H 'authorization: Bearer eyJhbGc....(fresh token)' \
  -H 'cookie: session=abc123; csrf=xyz789' \
  -H 'content-type: application/json' \
  --data-binary @- <<'EOF'
{"email":"usera@example.com","role":"admin"}
EOF

=== PARAMETERIZED ===
POST /users/{id}/profile

=== NOTES ===
User A session: session_1
User B session: session_2
Message ID: 42
Token refresh mode: playwright
```

## Summary

Session renewal makes the diff module a **viable alternative to Autorize** for scenarios requiring:
- Documentation and reproducibility
- Offline analysis
- Automated testing pipelines
- Custom scripting

The Playwright integration bridges the gap between static XML analysis and live token management.
