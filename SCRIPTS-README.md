# Running Playwright Scripts

All Playwright-related commands must be run from the `scripts/` directory:

## Setup (one-time)
```bash
cd scripts
npm install
```

## Running Commands

### CLI Mode (Interactive Menu)
```bash
cd scripts
npm run cli
# OR: node playwright-session-manager.js
```

### Test Mode

#### Record Mode
```bash
cd scripts
npm run test:record
# OR: npx playwright test --grep "record-mode" --headed
```

#### Replay Mode
```bash
cd scripts
npm run test:replay
```

#### Demo Test
```bash
cd scripts
npm run test:demo
```

#### mitmproxy Integration Tests
```bash
cd scripts
npm run test:mitm          # Run all
npm run test:mitm:alice    # Alice workflow
npm run test:mitm:bob      # Bob workflow
npm run test:mitm:multi    # Multi-user in single test
```

### Persistent Contexts (Cloudflare Protection)

**IMPORTANT**: Use persistent contexts for Cloudflare-protected sites to avoid verification loops.

```bash
cd scripts
npm run demo:persistent          # Show correct approach
npm run demo:persistent:wrong    # Show what NOT to do
npm run demo:persistent:compare  # Compare approaches
```

📖 **Full documentation**: See `scripts/CLOUDFLARE-PERSISTENT-CONTEXTS.md`

**Key concept**: Persistent contexts preserve cookies, TLS fingerprint, and browser entropy — preventing Cloudflare verification loops. This is the ONLY architecturally sound solution.

## Directory Structure
```
idor-analysis-template/
├── scripts/                 ← Work from here!
│   ├── package.json
│   ├── playwright-session-manager.js (library)
│   ├── playwright-session-tests.spec.js (tests)
│   └── node_modules/
└── [other project files]
```
