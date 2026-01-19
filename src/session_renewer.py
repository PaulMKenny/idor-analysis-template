#!/usr/bin/env python3
"""
Session Token Renewal Module

Provides mechanisms to refresh authentication tokens for User B
before replaying User A's requests in IDOR testing.

Supports:
- Playwright browser automation (headless/headed login)
- Manual token entry
- Token extraction from browser cookies and headers
"""

import json
import re
from pathlib import Path
from typing import Optional


class SessionRenewer:
    """
    Handles session token renewal for IDOR testing.
    """

    def __init__(self, session_root: Path):
        """
        Initialize session renewer.

        Args:
            session_root: Path to session directory (e.g., sessions/session_2/)
        """
        self.session_root = session_root
        self.config_file = session_root / "login_config.json"
        self.config = self._load_config()

    def _load_config(self) -> dict:
        """Load login configuration from session directory."""
        if not self.config_file.exists():
            return {}

        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Could not load login config: {e}")
            return {}

    def save_config(self, config: dict):
        """Save login configuration to session directory."""
        self.config = config
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Saved login config to {self.config_file}")

    def get_fresh_tokens_playwright(self, headless: bool = True) -> Optional[dict]:
        """
        Use Playwright to automate login and extract tokens.

        Args:
            headless: Whether to run browser in headless mode

        Returns:
            dict with 'cookies' and 'headers', or None if failed
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("[!] Error: Playwright not installed.")
            print("[!] Install with: pip install playwright")
            print("[!] Then run: playwright install chromium")
            return None

        if not self.config:
            print("[!] Error: No login configuration found.")
            print("[!] Run option to create config first.")
            return None

        login_url = self.config.get('login_url')
        selectors = self.config.get('selectors', {})
        credentials = self.config.get('credentials', {})

        if not all([login_url, selectors, credentials]):
            print("[!] Error: Incomplete login configuration.")
            return None

        print(f"[*] Launching browser{'(headless)' if headless else ''}...")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context()
            page = context.new_page()

            try:
                print(f"[*] Navigating to {login_url}")
                page.goto(login_url, wait_until='networkidle')

                # Fill username
                username_sel = selectors.get('username')
                if username_sel:
                    print(f"[*] Filling username")
                    page.fill(username_sel, credentials.get('username', ''))

                # Fill password
                password_sel = selectors.get('password')
                if password_sel:
                    print(f"[*] Filling password")
                    page.fill(password_sel, credentials.get('password', ''))

                # Click submit
                submit_sel = selectors.get('submit')
                if submit_sel:
                    print(f"[*] Clicking submit")
                    page.click(submit_sel)

                # Wait for navigation/success indicator
                success_indicator = self.config.get('success_indicator', {})
                if success_indicator.get('type') == 'url_contains':
                    expected_url = success_indicator.get('value')
                    print(f"[*] Waiting for URL to contain: {expected_url}")
                    page.wait_for_url(f"**/*{expected_url}*", timeout=10000)
                elif success_indicator.get('type') == 'element':
                    expected_element = success_indicator.get('value')
                    print(f"[*] Waiting for element: {expected_element}")
                    page.wait_for_selector(expected_element, timeout=10000)
                else:
                    # Default: wait a bit
                    print(f"[*] Waiting 3 seconds for login to complete")
                    page.wait_for_timeout(3000)

                # Extract cookies
                cookies = context.cookies()
                cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])

                # Extract authorization header if configured
                auth_header = None
                auth_config = self.config.get('auth_header_extraction')
                if auth_config:
                    # Try to extract from localStorage/sessionStorage
                    storage_key = auth_config.get('storage_key')
                    if storage_key:
                        try:
                            token = page.evaluate(f"localStorage.getItem('{storage_key}') || sessionStorage.getItem('{storage_key}')")
                            if token:
                                auth_prefix = auth_config.get('prefix', 'Bearer')
                                auth_header = f"{auth_prefix} {token}"
                        except Exception as e:
                            print(f"[!] Could not extract auth header: {e}")

                print(f"[+] Successfully logged in!")
                print(f"[+] Extracted {len(cookies)} cookies")

                result = {
                    'cookies': cookie_header,
                    'headers': {}
                }

                if auth_header:
                    result['headers']['authorization'] = auth_header
                    print(f"[+] Extracted authorization header")

                return result

            except Exception as e:
                print(f"[!] Error during login automation: {e}")
                return None
            finally:
                browser.close()

    def get_fresh_tokens_manual(self) -> Optional[dict]:
        """
        Prompt user to manually enter fresh tokens.

        Returns:
            dict with 'cookies' and 'headers', or None if cancelled
        """
        print("\n=== Manual Token Entry ===")
        print("Tip: Get fresh tokens from Burp Suite > Proxy > HTTP History")
        print("      Or from Browser DevTools > Network tab")
        print()

        cookie = input("Enter fresh Cookie header value (or press Enter to skip): ").strip()
        auth = input("Enter fresh Authorization header value (or press Enter to skip): ").strip()

        if not cookie and not auth:
            print("[!] No tokens entered.")
            return None

        result = {
            'cookies': cookie if cookie else None,
            'headers': {}
        }

        if auth:
            result['headers']['authorization'] = auth

        print("[+] Tokens saved for this session.")
        return result

    def configure_login_flow(self):
        """
        Interactive wizard to configure login flow for Playwright automation.
        """
        print("\n=== Configure Login Flow ===")
        print("This will create a configuration for automated login.")
        print()

        login_url = input("Login page URL: ").strip()
        if not login_url:
            print("[!] Login URL required.")
            return

        print("\n--- CSS Selectors ---")
        print("Tip: Right-click element in browser > Inspect > Copy > Copy selector")
        username_sel = input("Username field selector (e.g., #username): ").strip()
        password_sel = input("Password field selector (e.g., #password): ").strip()
        submit_sel = input("Submit button selector (e.g., button[type='submit']): ").strip()

        print("\n--- Credentials ---")
        print("Warning: Stored in plaintext in session directory!")
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        print("\n--- Success Indicator ---")
        print("How to detect successful login?")
        print("1) URL contains text (e.g., '/dashboard')")
        print("2) Element appears (e.g., '.user-menu')")
        print("3) None (just wait 3 seconds)")

        success_type = input("Choice [1/2/3]: ").strip()
        success_indicator = {}

        if success_type == "1":
            url_part = input("URL should contain: ").strip()
            success_indicator = {'type': 'url_contains', 'value': url_part}
        elif success_type == "2":
            element = input("Element selector: ").strip()
            success_indicator = {'type': 'element', 'value': element}

        print("\n--- Authorization Header (Optional) ---")
        print("Some apps store JWT in localStorage/sessionStorage")
        extract_auth = input("Extract auth header from browser storage? [y/N]: ").strip().lower()

        auth_config = None
        if extract_auth == 'y':
            storage_key = input("Storage key (e.g., 'auth_token'): ").strip()
            prefix = input("Header prefix (e.g., 'Bearer'): ").strip() or "Bearer"
            auth_config = {
                'storage_key': storage_key,
                'prefix': prefix
            }

        config = {
            'login_url': login_url,
            'selectors': {
                'username': username_sel,
                'password': password_sel,
                'submit': submit_sel
            },
            'credentials': {
                'username': username,
                'password': password
            },
            'success_indicator': success_indicator
        }

        if auth_config:
            config['auth_header_extraction'] = auth_config

        self.save_config(config)

        print("\n[+] Configuration saved!")
        print(f"[+] You can now use automated token renewal for {self.session_root.name}")


def select_token_refresh_mode() -> str:
    """
    Prompt user to select token refresh mode.

    Returns:
        'playwright', 'manual', or 'skip'
    """
    print("\n=== Token Refresh Mode ===")
    print("1) Playwright automation (recommended)")
    print("2) Manual token entry")
    print("3) Skip (use stale tokens from XML)")
    print()

    choice = input("Select mode [1/2/3]: ").strip()

    if choice == "1":
        return "playwright"
    elif choice == "2":
        return "manual"
    else:
        return "skip"


def merge_fresh_tokens(old_headers: dict, fresh_tokens: dict) -> dict:
    """
    Merge fresh tokens into headers dict.

    Args:
        old_headers: Original headers from User B's XML
        fresh_tokens: Fresh tokens from SessionRenewer

    Returns:
        Updated headers dict
    """
    headers = dict(old_headers)

    # Update cookie if present
    if fresh_tokens.get('cookies'):
        headers['cookie'] = fresh_tokens['cookies']
        print("[+] Updated Cookie header with fresh tokens")

    # Update authorization if present
    if fresh_tokens.get('headers', {}).get('authorization'):
        headers['authorization'] = fresh_tokens['headers']['authorization']
        print("[+] Updated Authorization header with fresh token")

    return headers
