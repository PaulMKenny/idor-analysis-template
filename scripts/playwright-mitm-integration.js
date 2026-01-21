/**
 * Playwright + mitmproxy Integration
 *
 * Provides helpers to signal action boundaries to mitmproxy via marker requests.
 * This enables partitioned traffic capture: User → Session → Action
 */

const { test } = require('@playwright/test');

/**
 * ActionManager - Coordinates Playwright actions with mitmproxy capture
 *
 * Usage:
 *   const actions = new ActionManager(page, 'alice', 'session-1', logger);
 *   await actions.start('navigate to projects');
 *   await page.goto('https://app.com/projects');
 */
class ActionManager {
  constructor(page, user, session, logger = null) {
    this.page = page;
    this.user = user;
    this.session = session;
    this.logger = logger; // Optional: existing ActionAwareRequestLogger
    this.proxyUrl = 'http://127.0.0.1:8080';
  }

  /**
   * Start a new action - signals mitmproxy and optionally logs to Playwright logger
   */
  async start(actionName) {
    // 1. Signal mitmproxy via marker request
    await this.page.evaluate(async ({ proxyUrl, user, session, actionName }) => {
      try {
        const response = await fetch(`${proxyUrl}/__ui_action_marker__`, {
          method: 'POST',
          headers: {
            'X-Test-User': user,
            'X-UI-Session': session,
            'X-UI-Action': actionName
          }
        });

        if (!response.ok) {
          console.warn(`[marker] Failed: ${response.status}`);
        } else {
          const data = await response.json();
          console.log(`[marker] ${data.status}: ${data.action}`);
        }
      } catch (e) {
        console.warn(`[marker] Request failed (mitmproxy not running?): ${e.message}`);
      }
    }, {
      proxyUrl: this.proxyUrl,
      user: this.user,
      session: this.session,
      actionName
    });

    // 2. Start Playwright logging (if logger provided)
    if (this.logger) {
      this.logger.startAction(actionName);
    }

    // 3. Brief delay to ensure partition is ready
    await this.page.waitForTimeout(50);
  }

  /**
   * Convenience method: send marker without starting logger
   */
  async signal(actionName) {
    await this.page.evaluate(async ({ proxyUrl, user, session, actionName }) => {
      try {
        await fetch(`${proxyUrl}/__ui_action_marker__`, {
          method: 'POST',
          headers: {
            'X-Test-User': user,
            'X-UI-Session': session,
            'X-UI-Action': actionName
          }
        });
      } catch (e) {
        // Ignore - marker may fail if mitmproxy not running
      }
    }, {
      proxyUrl: this.proxyUrl,
      user: this.user,
      session: this.session,
      actionName
    });

    await this.page.waitForTimeout(50);
  }
}

/**
 * Test configuration for mitmproxy proxy
 */
const mitmproxyConfig = {
  proxy: { server: 'http://127.0.0.1:8080' },
  ignoreHTTPSErrors: true
};

/**
 * Helper to check if mitmproxy is running
 */
async function checkMitmproxy(page) {
  try {
    const response = await page.evaluate(async () => {
      const res = await fetch('http://127.0.0.1:8080/__ui_action_marker__', {
        method: 'POST',
        headers: {
          'X-Test-User': 'test',
          'X-UI-Session': 'test',
          'X-UI-Action': 'test'
        }
      });
      return res.ok;
    });
    return response;
  } catch (e) {
    return false;
  }
}

module.exports = {
  ActionManager,
  mitmproxyConfig,
  checkMitmproxy
};
