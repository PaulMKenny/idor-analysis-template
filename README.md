# IDOR Analysis Template

Comprehensive toolkit for identifying and testing Insecure Direct Object Reference (IDOR) vulnerabilities through automated HTTP traffic analysis and UI automation.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install playwright
playwright install chromium
```

### 2. Record User Actions

```bash
python scripts/ui_automation.py --profile ~/pw-profiles/admin --session 1

# Interactive REPL
[UI-Auto] > goto https://target.com/dashboard
[UI-Auto] > click text=Users
[UI-Auto] > mark "Navigate to users"
[UI-Auto] > save baseline.json
[UI-Auto] > quit
```

### 3. Test with Multiple Users

```bash
# Create profiles.json (see examples/profiles.json)
python scripts/multi_user_idor_test.py baseline.json --profiles profiles.json
```

### 4. Review Results

```bash
# View comparison report
cat idor_comparison.txt

# View detailed analysis
cat sessions/session_100/output/history_100_idor_triage.txt
```

---

## 📁 Repository Structure

```
idor-analysis-template/
├── src/
│   ├── bookmark.py              # Action boundary tracking
│   ├── idor_analyzer.py         # Main IDOR detection engine
│   ├── idor_permutator.py       # Mutation generator
│   ├── raw_http_dump.py         # HTTP message inspector
│   └── sitemap_extractor.py     # Endpoint tree builder
├── scripts/
│   ├── ui_automation.py         # ✨ Interactive UI automation (NEW)
│   ├── multi_user_idor_test.py  # ✨ Multi-user comparison (NEW)
│   └── idor_interface.py        # Session manager CLI
├── docs/
│   └── UI_AUTOMATION_GUIDE.md   # ✨ Complete automation guide (NEW)
├── examples/
│   ├── profiles.json            # ✨ Example user profiles (NEW)
│   └── baseline_actions_example.json  # ✨ Example action sequence (NEW)
└── sessions/
    └── session_N/
        ├── input/               # HTTP captures (Burp XML)
        └── output/              # Analysis results
```

---

## 🎯 Key Features

### UI Automation (NEW)

- **Interactive REPL** - Build test sequences iteratively, not hardcoded
- **Full HTTP Capture** - Burp XML format compatible with existing analyzers
- **Action Bookmarks** - Correlate UI actions with HTTP requests
- **Save/Replay** - Record sequences and replay across multiple users
- **Multi-User Testing** - Compare same actions with different privilege levels

### IDOR Analysis

- **Zero False Negatives** - Aggressive extraction, lazy filtering
- **Smart Scoring** - 100+ point scale based on multiple signals
- **Semantic Tiering** - Tier 1 (authorization) vs Tier 2 (informational)
- **GraphQL Support** - Extracts IDs from variables and operations
- **Token Binding Detection** - Identifies JWT/cookie-bound IDs
- **Co-occurrence Tracking** - Maps request IDs to response IDs

### Mutation Generation

- **Numeric Offsets** - ±1, boundaries (0, MAX_INT)
- **Structural Mutations** - Trailing slashes, case changes
- **Multi-step Chains** - Combine mutations (depth 1-3)
- **Format Variations** - String/int/UUID transformations

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [UI_AUTOMATION_GUIDE.md](docs/UI_AUTOMATION_GUIDE.md) | Complete guide for UI automation features |
| [idor_analyzer.py](src/idor_analyzer.py) | Inline documentation for analysis engine |
| [examples/](examples/) | Example configurations and action sequences |

---

## 🔄 Typical Workflow

### Manual Analysis (Traditional)

```bash
# 1. Capture HTTP in Burp, export XML
# 2. Run analyzer
cd sessions/session_1/output
python3 ../../src/idor_analyzer.py ../input/history_1.xml

# 3. Review candidates
cat history_1_idor_triage.txt

# 4. Generate mutations
python3 ../../src/idor_permutator.py ../input/history_1.xml 5 --format text

# 5. Test mutations manually in Burp/curl
```

### Automated Workflow (NEW)

```bash
# 1. Setup profiles (one-time)
mkdir -p ~/pw-profiles/{admin,user_a,user_b}
playwright open --user-data-dir ~/pw-profiles/admin https://target.com/login

# 2. Record actions interactively
python scripts/ui_automation.py --profile ~/pw-profiles/admin --session 1
[UI-Auto] > goto https://target.com/users
[UI-Auto] > click text=John Doe
[UI-Auto] > mark "View user detail"
[UI-Auto] > save baseline.json
[UI-Auto] > quit

# 3. Replay with multiple users (automatic analysis)
python scripts/multi_user_idor_test.py baseline.json --profiles examples/profiles.json

# 4. Review comparison report
cat idor_comparison.txt
```

---

## 🧪 Use Cases

### 1. Multi-Tenant Application Testing

**Goal:** Verify tenant A cannot access tenant B's resources.

```bash
# Record admin actions in tenant A
python scripts/ui_automation.py --profile ~/pw-profiles/tenant_a_admin --session 10
[UI-Auto] > goto https://app.com/dashboard
[UI-Auto] > click text=Reports
[UI-Auto] > mark "Access reports"
[UI-Auto] > save tenant_actions.json

# Test with tenant B user
python scripts/ui_automation.py --profile ~/pw-profiles/tenant_b_user --session 11 \
  --replay tenant_actions.json

# Compare
diff sessions/session_10/output/history_10_idor_candidates.csv \
     sessions/session_11/output/history_11_idor_candidates.csv
```

### 2. Role-Based Access Control (RBAC) Testing

**Goal:** Verify regular users cannot access admin endpoints.

```bash
# Multi-user test with different roles
cat > rbac_profiles.json <<EOF
{
  "admin": "~/pw-profiles/admin",
  "editor": "~/pw-profiles/editor",
  "viewer": "~/pw-profiles/viewer"
}
EOF

python scripts/multi_user_idor_test.py admin_actions.json --profiles rbac_profiles.json

# Review differential report
cat idor_comparison.txt | grep "POTENTIAL IDOR"
```

### 3. API Resource Authorization Testing

**Goal:** Find IDs that work across user contexts.

```bash
# Record API interactions
python scripts/ui_automation.py --profile ~/pw-profiles/user_a --session 20
[UI-Auto] > goto https://api.example.com/users/123
[UI-Auto] > mark "Fetch user 123"
[UI-Auto] > goto https://api.example.com/users/456
[UI-Auto] > mark "Fetch user 456"
[UI-Auto] > save api_test.json

# Replay as different user
python scripts/ui_automation.py --profile ~/pw-profiles/user_b --session 21 \
  --replay api_test.json

# Analyzer will flag if user_b successfully accesses user 123/456
```

---

## 🔍 What the Analyzer Looks For

### High-Priority Signals (Score Boosters)

- ✅ **High-signal keys**: `user_id`, `account_id`, `order_id`, `customer_id`
- ✅ **Selector-like sources**: Path/query/GraphQL variables
- ✅ **Mutation endpoints**: POST/PUT/DELETE methods
- ✅ **Dereferenced IDs**: ID used to fetch related data
- ✅ **Origin mixing**: ID appears in both request and response
- ✅ **Primary target host**: Main application domain

### Low-Priority Signals (Score Reducers)

- ⚠️ **Informational keys**: `timestamp`, `nonce`, `trace_id`, `session_id`
- ⚠️ **Third-party hosts**: Analytics, CDN, telemetry domains
- ⚠️ **Token-bound IDs**: ID embedded in JWT claims
- ⚠️ **Response-only IDs**: Server-generated, not user-controlled
- ⚠️ **Low-confidence parsing**: Ambiguous extraction patterns

### Scoring Example

```
Candidate: user_id=123 @ POST api.example.com/api/users/123

Base score:         1
+20: high-signal key (user_id)
+15: primary target host
+30: selector-like source (path)
+10: dereferenced (fetches user data)
+15: mutation endpoint (POST)
+10: origin mixing (request + response)
+5: appears in 3+ messages
─────────────────────
Final score:        106

Tier: 1 (authorization-relevant)
```

---

## 🛠️ Advanced Configuration

### Custom Capture Filters

Edit `scripts/ui_automation.py`:

```python
def _route_handler(self, route: Route, request: Request):
    # Skip third-party requests
    if any(domain in request.url for domain in ["google-analytics.com", "cdn.example.com"]):
        return route.continue_()

    # Only capture API calls
    if "/api/" not in request.url:
        return route.continue_()

    # Rest of capture logic...
```

### Custom Scoring Weights

Edit `src/idor_analyzer.py`:

```python
# Adjust scoring parameters
HIGH_SIGNAL_KEYS = ["user_id", "account_id", "tenant_id", "custom_id"]
KEY_SIGNAL_SCORE = 30  # Default: 20
MUTATION_SCORE = 20    # Default: 15
```

### CI/CD Integration

```yaml
# .github/workflows/idor-scan.yml
name: Daily IDOR Regression Test

on:
  schedule:
    - cron: '0 2 * * *'

jobs:
  idor-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install playwright && playwright install chromium
      - run: |
          python scripts/ui_automation.py \
            --replay baseline.json \
            --profile ${{ secrets.TEST_PROFILE }} \
            --session ${{ github.run_number }} \
            --headless
      - run: |
          cd sessions/session_${{ github.run_number }}/output
          python ../../../src/idor_analyzer.py ../input/history_*.xml
      - uses: actions/upload-artifact@v3
        with:
          name: idor-results
          path: sessions/*/output/*_idor_*.csv
```

---

## 🤝 Contributing

This is a template repository. Customize for your specific use case:

1. **Fork and adapt** - Modify scripts for your target application
2. **Add custom parsers** - Extend ID extraction for proprietary formats
3. **Integrate with your workflow** - Connect to existing security tools
4. **Share improvements** - Submit PRs for generic enhancements

---

## 📜 License

[Insert your license here]

---

## ⚠️ Disclaimer

This toolkit is for **authorized security testing only**. Always:

- ✅ Get explicit written permission before testing
- ✅ Test on non-production environments when possible
- ✅ Follow responsible disclosure practices
- ❌ Never use on systems you don't own or have permission to test
- ❌ Never test destructive operations in production

---

## 🎓 Learning Resources

- [OWASP IDOR Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger IDOR Labs](https://portswigger.net/web-security/access-control/idor)
- [Playwright Documentation](https://playwright.dev/python/docs/intro)
- [Burp XML Format](https://portswigger.net/burp/documentation/desktop/tools/proxy/history)

---

## 📧 Support

For questions or issues:
1. Check [UI_AUTOMATION_GUIDE.md](docs/UI_AUTOMATION_GUIDE.md) for detailed usage
2. Review example configurations in [examples/](examples/)
3. Open an issue with reproducible steps and sample data

**Happy hunting! 🔍🔐**
