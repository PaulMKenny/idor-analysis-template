#!/usr/bin/env python3
"""
Playwright Introduction Script for IDOR Testing

This self-contained script demonstrates the core Playwright concepts
you'll need for automated login and token extraction.

Prerequisites:
    pip install playwright
    playwright install chromium

Usage:
    python3 examples/playwright_intro.py
"""

import json
import time
from playwright.sync_api import sync_playwright


def demo_1_basic_navigation():
    """Demo 1: Launch browser and navigate to a page"""
    print("\n" + "="*60)
    print("DEMO 1: Basic Browser Launch & Navigation")
    print("="*60)

    with sync_playwright() as p:
        # Launch browser in VISIBLE mode (headless=False)
        print("[*] Launching visible browser...")
        browser = p.chromium.launch(headless=False)

        # Create a new browser context (like an incognito window)
        context = browser.new_context()

        # Create a new page (tab)
        page = context.new_page()

        # Navigate to a website
        print("[*] Navigating to example.com...")
        page.goto("https://example.com")

        # Get the page title
        title = page.title()
        print(f"[+] Page title: {title}")

        # Wait so you can see it
        print("[*] Waiting 3 seconds (watch the browser)...")
        time.sleep(3)

        # Clean up
        browser.close()
        print("[+] Browser closed\n")


def demo_2_form_interaction():
    """Demo 2: Fill forms and click buttons (using example.com for demo)"""
    print("\n" + "="*60)
    print("DEMO 2: Form Interaction (Selectors & Actions)")
    print("="*60)

    # We'll use a simple HTML page to demonstrate
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Login Demo</title></head>
    <body>
        <h1>Mock Login Page</h1>
        <form id="loginForm">
            <input id="username" type="text" placeholder="Username" />
            <input id="password" type="password" placeholder="Password" />
            <button type="submit" id="loginBtn">Login</button>
        </form>
        <div id="result" style="display:none; color: green;">
            Login successful! Welcome, <span id="userName"></span>
        </div>
        <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const username = document.getElementById('username').value;
                document.getElementById('userName').textContent = username;
                document.getElementById('result').style.display = 'block';
                // Store token in localStorage (simulating JWT storage)
                localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock_token');
            });
        </script>
    </body>
    </html>
    """

    # Save to temp file
    import tempfile
    import os
    temp_dir = tempfile.mkdtemp()
    html_path = os.path.join(temp_dir, "login.html")
    with open(html_path, "w") as f:
        f.write(html_content)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        # Load our mock login page
        print(f"[*] Loading mock login page from: {html_path}")
        page.goto(f"file://{html_path}")

        # FINDING ELEMENTS (CSS Selectors)
        print("\n--- CSS Selector Methods ---")
        print("[*] Finding username field using: #username")
        print("[*] Finding password field using: #password")
        print("[*] Finding submit button using: #loginBtn")

        # FILLING FORMS
        print("\n--- Filling Form ---")
        print("[*] Typing username: 'testuser'")
        page.fill("#username", "testuser")

        print("[*] Typing password: 'password123'")
        page.fill("#password", "password123")

        time.sleep(1)  # So you can see it

        # CLICKING BUTTONS
        print("\n--- Clicking Button ---")
        print("[*] Clicking login button")
        page.click("#loginBtn")

        # WAITING FOR ELEMENTS
        print("\n--- Waiting for Success Message ---")
        print("[*] Waiting for #result element to appear...")
        page.wait_for_selector("#result", state="visible", timeout=5000)
        print("[+] Success message appeared!")

        time.sleep(2)

        browser.close()
        print("[+] Demo complete\n")

        # Cleanup
        os.remove(html_path)


def demo_3_token_extraction():
    """Demo 3: Extract cookies and localStorage tokens (the key skill!)"""
    print("\n" + "="*60)
    print("DEMO 3: Token Extraction (Cookies & localStorage)")
    print("="*60)
    print("This is the CORE SKILL for IDOR testing!\n")

    # Create a more realistic mock page with cookies and localStorage
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Token Extraction Demo</title></head>
    <body>
        <h1>Session Token Demo</h1>
        <button id="login">Simulate Login</button>
        <div id="status"></div>
        <script>
            document.getElementById('login').addEventListener('click', function() {
                // Set cookies (like a real app would)
                document.cookie = 'session_id=abc123xyz; path=/';
                document.cookie = 'csrf_token=def456uvw; path=/';

                // Store JWT in localStorage (common pattern)
                localStorage.setItem('jwt_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0fQ.mock_signature');

                // Store refresh token in sessionStorage
                sessionStorage.setItem('refresh_token', 'refresh_abc123');

                document.getElementById('status').textContent = 'Logged in! Tokens stored.';
            });
        </script>
    </body>
    </html>
    """

    import tempfile
    import os
    temp_dir = tempfile.mkdtemp()
    html_path = os.path.join(temp_dir, "tokens.html")
    with open(html_path, "w") as f:
        f.write(html_content)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        page.goto(f"file://{html_path}")

        print("[*] Clicking login button to set tokens...")
        page.click("#login")
        page.wait_for_selector("#status")
        time.sleep(1)

        # ===== EXTRACT COOKIES =====
        print("\n--- Extracting Cookies ---")
        cookies = context.cookies()

        print(f"[+] Found {len(cookies)} cookies:")
        for cookie in cookies:
            print(f"    {cookie['name']} = {cookie['value']}")

        # Format as Cookie header (what you need for curl)
        cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        print(f"\n[+] Cookie header format:")
        print(f"    Cookie: {cookie_header}")

        # ===== EXTRACT localStorage =====
        print("\n--- Extracting localStorage ---")
        jwt_token = page.evaluate("localStorage.getItem('jwt_token')")
        print(f"[+] JWT token: {jwt_token}")

        # Format as Authorization header
        if jwt_token:
            auth_header = f"Bearer {jwt_token}"
            print(f"\n[+] Authorization header format:")
            print(f"    Authorization: {auth_header}")

        # ===== EXTRACT sessionStorage =====
        print("\n--- Extracting sessionStorage ---")
        refresh_token = page.evaluate("sessionStorage.getItem('refresh_token')")
        print(f"[+] Refresh token: {refresh_token}")

        # ===== ALL TOKENS TOGETHER =====
        print("\n" + "="*60)
        print("TOKENS READY FOR CURL COMMAND:")
        print("="*60)
        tokens = {
            'cookies': cookie_header,
            'headers': {
                'authorization': auth_header if jwt_token else None
            }
        }
        print(json.dumps(tokens, indent=2))

        time.sleep(2)
        browser.close()
        print("\n[+] Demo complete\n")

        os.remove(html_path)


def demo_4_success_detection():
    """Demo 4: Different ways to detect successful login"""
    print("\n" + "="*60)
    print("DEMO 4: Success Detection Methods")
    print("="*60)
    print("How to know when login succeeded?\n")

    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>Success Detection Demo</title></head>
    <body>
        <h1>Login Page</h1>
        <button id="login">Login</button>
        <script>
            document.getElementById('login').addEventListener('click', function() {
                // Simulate redirect after login
                setTimeout(() => {
                    window.location.hash = '#dashboard';

                    // Add a user menu that only appears when logged in
                    const menu = document.createElement('div');
                    menu.className = 'user-menu';
                    menu.textContent = 'Welcome, User!';
                    document.body.appendChild(menu);
                }, 1000);
            });
        </script>
    </body>
    </html>
    """

    import tempfile
    import os
    temp_dir = tempfile.mkdtemp()
    html_path = os.path.join(temp_dir, "success.html")
    with open(html_path, "w") as f:
        f.write(html_content)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        page.goto(f"file://{html_path}")

        print("[*] Clicking login...")
        page.click("#login")

        # METHOD 1: Wait for URL change
        print("\n--- Method 1: URL Contains ---")
        print("[*] Waiting for URL to contain '#dashboard'...")
        page.wait_for_url("**/#dashboard", timeout=5000)
        print(f"[+] Success! URL is now: {page.url}")

        # METHOD 2: Wait for element to appear
        print("\n--- Method 2: Element Appears ---")
        print("[*] Waiting for .user-menu element...")
        page.wait_for_selector(".user-menu", state="visible", timeout=5000)
        print("[+] Success! User menu appeared")

        # METHOD 3: Just wait (fallback)
        print("\n--- Method 3: Time Delay ---")
        print("[*] Waiting 2 seconds...")
        time.sleep(2)
        print("[+] Assumed success after timeout")

        browser.close()
        print("\n[+] Demo complete\n")

        os.remove(html_path)


def demo_5_headless_mode():
    """Demo 5: Headless vs Visible mode"""
    print("\n" + "="*60)
    print("DEMO 5: Headless Mode (Invisible Browser)")
    print("="*60)
    print("Production use: headless=True (no GUI, faster)")
    print("Debugging: headless=False (see what's happening)\n")

    with sync_playwright() as p:
        # Headless mode (invisible)
        print("[*] Launching HEADLESS browser (you won't see it)...")
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        print("[*] Navigating to example.com...")
        page.goto("https://example.com")

        title = page.title()
        print(f"[+] Page title: {title}")
        print("[*] Browser is invisible - running in background")

        browser.close()
        print("[+] Headless browser closed")

        print("\n[*] Now launching VISIBLE browser for comparison...")
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()

        page.goto("https://example.com")
        print("[*] You should see the browser window now!")
        time.sleep(2)

        browser.close()
        print("[+] Visible browser closed\n")


def demo_6_real_world_example():
    """Demo 6: Putting it all together - realistic login flow"""
    print("\n" + "="*60)
    print("DEMO 6: Complete Real-World Login Flow")
    print("="*60)
    print("This simulates the exact workflow used in the IDOR tool\n")

    # Realistic login page with all features
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Realistic Login</title>
        <style>
            body { font-family: Arial; max-width: 400px; margin: 50px auto; }
            input { width: 100%; padding: 10px; margin: 10px 0; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
            .dashboard { display: none; }
            .user-menu { background: #28a745; color: white; padding: 10px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div id="loginPage">
            <h2>Login</h2>
            <form id="loginForm">
                <input id="email" type="email" placeholder="Email" required />
                <input id="password" type="password" placeholder="Password" required />
                <button type="submit">Login</button>
            </form>
        </div>
        <div id="dashboard" class="dashboard">
            <div class="user-menu">
                Welcome, <span id="userName"></span>!
            </div>
            <h2>Dashboard</h2>
            <p>You are logged in.</p>
        </div>
        <script>
            document.getElementById('loginForm').addEventListener('submit', function(e) {
                e.preventDefault();

                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;

                // Simulate server delay
                setTimeout(() => {
                    // Set cookies
                    document.cookie = 'session_id=sess_' + Date.now() + '; path=/';
                    document.cookie = 'csrf_token=csrf_' + Math.random().toString(36).substr(2, 9) + '; path=/';

                    // Store JWT
                    const mockJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
                                   btoa(JSON.stringify({email: email, exp: Date.now() + 3600000})) +
                                   '.mock_signature';
                    localStorage.setItem('auth_token', mockJWT);

                    // Show dashboard
                    document.getElementById('loginPage').style.display = 'none';
                    document.getElementById('dashboard').style.display = 'block';
                    document.getElementById('userName').textContent = email;

                    // Change URL
                    window.location.hash = '#dashboard';
                }, 500);
            });
        </script>
    </body>
    </html>
    """

    import tempfile
    import os
    temp_dir = tempfile.mkdtemp()
    html_path = os.path.join(temp_dir, "realistic.html")
    with open(html_path, "w") as f:
        f.write(html_content)

    # This is the pattern used in session_renewer.py
    config = {
        'login_url': f'file://{html_path}',
        'selectors': {
            'username': '#email',
            'password': '#password',
            'submit': 'button[type="submit"]'
        },
        'credentials': {
            'username': 'testuser@example.com',
            'password': 'password123'
        },
        'success_indicator': {
            'type': 'url_contains',
            'value': '#dashboard'
        },
        'auth_header_extraction': {
            'storage_key': 'auth_token',
            'prefix': 'Bearer'
        }
    }

    print("Configuration:")
    print(json.dumps(config, indent=2))

    with sync_playwright() as p:
        print("\n[*] Launching browser (headless)...")
        browser = p.chromium.launch(headless=True)  # Try headless=False to watch
        context = browser.new_context()
        page = context.new_page()

        try:
            # Step 1: Navigate
            print(f"[*] Navigating to login page...")
            page.goto(config['login_url'], wait_until='networkidle')

            # Step 2: Fill username
            print(f"[*] Filling username: {config['credentials']['username']}")
            page.fill(config['selectors']['username'], config['credentials']['username'])

            # Step 3: Fill password
            print(f"[*] Filling password: ********")
            page.fill(config['selectors']['password'], config['credentials']['password'])

            # Step 4: Submit
            print(f"[*] Clicking submit button")
            page.click(config['selectors']['submit'])

            # Step 5: Wait for success
            success_value = config['success_indicator']['value']
            print(f"[*] Waiting for URL to contain: {success_value}")
            page.wait_for_url(f"**/*{success_value}*", timeout=10000)

            print(f"[+] Successfully logged in!")

            # Step 6: Extract cookies
            cookies = context.cookies()
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            print(f"\n[+] Extracted {len(cookies)} cookies")

            # Step 7: Extract auth header
            storage_key = config['auth_header_extraction']['storage_key']
            token = page.evaluate(f"localStorage.getItem('{storage_key}')")

            auth_header = None
            if token:
                prefix = config['auth_header_extraction']['prefix']
                auth_header = f"{prefix} {token}"
                print(f"[+] Extracted authorization header")

            # Step 8: Return tokens
            result = {
                'cookies': cookie_header,
                'headers': {
                    'authorization': auth_header
                }
            }

            print("\n" + "="*60)
            print("FINAL RESULT (Ready for IDOR testing):")
            print("="*60)
            print(json.dumps(result, indent=2))

            print("\n" + "="*60)
            print("HOW THIS GETS USED IN CURL:")
            print("="*60)
            print("curl -X POST 'https://api.example.com/users/1234/profile' \\")
            print(f"  -H 'cookie: {cookie_header}' \\")
            print(f"  -H 'authorization: {auth_header}' \\")
            print("  --data-binary @- <<'EOF'")
            print('{"email":"usera@example.com"}')
            print("EOF")

        except Exception as e:
            print(f"\n[!] Error: {e}")

        finally:
            browser.close()
            print("\n[+] Browser closed")

        os.remove(html_path)


def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("PLAYWRIGHT INTRODUCTION FOR IDOR TESTING")
    print("="*60)
    print("\nThis script demonstrates the key Playwright concepts you need")
    print("for automated login and token extraction in IDOR testing.\n")

    demos = [
        ("Basic Navigation", demo_1_basic_navigation),
        ("Form Interaction", demo_2_form_interaction),
        ("Token Extraction", demo_3_token_extraction),
        ("Success Detection", demo_4_success_detection),
        ("Headless Mode", demo_5_headless_mode),
        ("Real-World Example", demo_6_real_world_example),
    ]

    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n{'='*60}")
        print(f"Demo {i}/{len(demos)}: {name}")
        print(f"{'='*60}")

        choice = input("\nPress ENTER to run this demo (or 'q' to quit): ").strip().lower()
        if choice == 'q':
            print("\nExiting. Run again to see remaining demos.")
            break

        try:
            demo_func()
        except Exception as e:
            print(f"\n[!] Demo error: {e}")
            print("[!] Make sure Playwright is installed:")
            print("    pip install playwright")
            print("    playwright install chromium")
            import traceback
            traceback.print_exc()
            break

    print("\n" + "="*60)
    print("SUMMARY: Key Takeaways")
    print("="*60)
    print("""
1. sync_playwright() - Main entry point
2. browser.launch(headless=True/False) - Start browser
3. page.goto(url) - Navigate to page
4. page.fill(selector, text) - Fill form fields
5. page.click(selector) - Click buttons
6. page.wait_for_url(pattern) - Wait for navigation
7. context.cookies() - Extract cookies
8. page.evaluate(js_code) - Run JavaScript to get localStorage
9. Format as headers for curl commands

For IDOR testing, the workflow is:
  1. Navigate to login page
  2. Fill username & password
  3. Click submit
  4. Wait for success indicator
  5. Extract cookies & localStorage tokens
  6. Format as headers for curl commands
  7. Use in User A vs User B diff testing

Next steps:
  - Try Feature 7 (Configure Login) in the main tool
  - Run Feature 8 (Diff + Replay) with Playwright mode
  - Test against your own applications
""")


if __name__ == "__main__":
    main()
