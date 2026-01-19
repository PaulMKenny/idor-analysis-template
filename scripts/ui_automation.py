#!/usr/bin/env python3
"""
Interactive UI Automation Script for IDOR Analysis

Features:
- REPL mode for iterative action building (not hardcoded)
- Full HTTP capture in Burp XML format
- Action boundary tracking with ActionBookmark
- Multi-user profile support for IDOR comparison
- Action sequence save/replay
- Session directory integration

Usage:
    python ui_automation.py --profile admin --session 1
    python ui_automation.py --replay actions.json --profile user_a --session 2
"""

import argparse
import base64
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional, Dict

from playwright.sync_api import sync_playwright, Page, BrowserContext, Request, Route

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from bookmark import ActionBookmark


class BurpXMLCapture:
    """
    Captures HTTP traffic and writes to Burp XML format.

    Compatible with idor_analyzer.py input requirements.
    """

    def __init__(self, xml_path: str):
        self.xml_path = xml_path
        self.request_response_pairs: List[Tuple[bytes, bytes]] = []

        # Initialize XML structure
        if not os.path.exists(xml_path):
            root = ET.Element("items")
            tree = ET.ElementTree(root)
            tree.write(xml_path, encoding="UTF-8", xml_declaration=True)

    def add_pair(self, request_bytes: bytes, response_bytes: bytes):
        """Add HTTP request/response pair to buffer."""
        self.request_response_pairs.append((request_bytes, response_bytes))

    def flush(self):
        """Write buffered pairs to XML file."""
        if not self.request_response_pairs:
            return

        # Parse existing XML
        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        # Add new items
        for req_bytes, resp_bytes in self.request_response_pairs:
            item = ET.SubElement(root, "item")

            req_elem = ET.SubElement(item, "request", attrib={"base64": "true"})
            req_elem.text = base64.b64encode(req_bytes).decode('ascii')

            resp_elem = ET.SubElement(item, "response", attrib={"base64": "true"})
            resp_elem.text = base64.b64encode(resp_bytes).decode('ascii')

        # Write back
        tree.write(self.xml_path, encoding="UTF-8", xml_declaration=True)

        count = len(self.request_response_pairs)
        self.request_response_pairs.clear()
        print(f"[CAPTURE] Flushed {count} HTTP pairs to {self.xml_path}")


class UIAutomation:
    """
    Interactive UI automation with HTTP capture for IDOR analysis.
    """

    def __init__(self, profile_dir: str, session_num: int, headless: bool = False):
        self.profile_dir = profile_dir
        self.session_num = session_num
        self.headless = headless

        # Setup session directories
        self.session_dir = Path(f"sessions/session_{session_num}")
        self.session_dir.mkdir(parents=True, exist_ok=True)
        (self.session_dir / "input").mkdir(exist_ok=True)
        (self.session_dir / "output").mkdir(exist_ok=True)

        # Setup capture files
        self.burp_xml_path = str(self.session_dir / "input" / f"history_{session_num}.xml")
        self.bookmark_path = str(self.session_dir / "input" / f"actions_{session_num}.json")

        # Initialize components
        self.bookmark = ActionBookmark(self.bookmark_path)
        self.capture = BurpXMLCapture(self.burp_xml_path)
        self.current_action_id = 0

        # Action history for replay
        self.action_history: List[Tuple] = []

    def _build_http_request(self, request: Request) -> bytes:
        """Build full HTTP request bytes from Playwright Request."""
        lines = []

        # Request line
        url_obj = request.url
        path = url_obj.split(request.headers.get("host", ""), 1)[-1]
        if not path.startswith("/"):
            path = "/" + path.split("/", 3)[-1] if "/" in url_obj else "/"

        lines.append(f"{request.method} {path} HTTP/1.1")

        # Headers
        for name, value in request.headers.items():
            lines.append(f"{name}: {value}")

        lines.append("")  # Empty line before body

        http_head = "\r\n".join(lines)

        # Body
        post_data = request.post_data
        if post_data:
            if isinstance(post_data, str):
                post_data = post_data.encode('utf-8')
            return http_head.encode('utf-8') + b"\r\n" + post_data

        return http_head.encode('utf-8') + b"\r\n"

    def _build_http_response(self, response) -> bytes:
        """Build full HTTP response bytes from Playwright Response."""
        lines = []

        # Status line
        lines.append(f"HTTP/1.1 {response.status} {response.status_text}")

        # Headers
        for name, value in response.headers.items():
            lines.append(f"{name}: {value}")

        lines.append("")  # Empty line before body

        http_head = "\r\n".join(lines)

        # Body
        try:
            body = response.body()
        except Exception:
            body = b""

        return http_head.encode('utf-8') + b"\r\n" + body

    def _route_handler(self, route: Route, request: Request):
        """
        Intercept requests to capture full HTTP messages.

        This is the critical piece that gets full request + response.
        """
        # Fetch the actual response
        response = route.fetch()

        # Build full HTTP messages
        req_bytes = self._build_http_request(request)
        resp_bytes = self._build_http_response(response)

        # Add to capture buffer
        self.capture.add_pair(req_bytes, resp_bytes)

        # Log for debugging
        print(f"[HTTP {self.current_action_id}] {request.method} {request.url[:80]} → {response.status}")

        # Fulfill the response (complete the route)
        route.fulfill(response=response)

    def mark(self, description: str, metadata: Optional[Dict] = None):
        """Mark action boundary and flush HTTP capture."""
        self.current_action_id = self.bookmark.mark(description, metadata)
        self.capture.flush()

    def run_interactive(self):
        """Start interactive REPL session."""
        print(f"""
{'='*70}
INTERACTIVE UI AUTOMATION - IDOR ANALYSIS
{'='*70}
Session: {self.session_num}
Profile: {self.profile_dir}
Output:  {self.burp_xml_path}

Commands:
  goto <url>              - Navigate to URL
  click <selector>        - Click element (CSS/text selector)
  fill <selector>|<value> - Fill input field
  press <key>             - Press keyboard key
  wait <ms>               - Wait for milliseconds
  wait_for <selector>     - Wait for element to appear
  mark <description>      - Mark action boundary (flush HTTP capture)

  save <filename>         - Save action sequence for replay
  list                    - Show available commands
  history                 - Show action history
  quit                    - Exit and save session
{'='*70}
""")

        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=self.profile_dir,
                headless=self.headless,
            )

            # Setup HTTP interception
            context.route("**/*", self._route_handler)

            page = context.new_page()

            # Initial mark
            self.mark("Session start")

            # REPL loop
            while True:
                try:
                    cmd = input("\n[UI-Auto] > ").strip()

                    if not cmd:
                        continue

                    parts = cmd.split(maxsplit=1)
                    action = parts[0]
                    args = parts[1] if len(parts) > 1 else ""

                    if action == "goto":
                        page.goto(args)
                        self.action_history.append(("goto", args))
                        print(f"✓ Navigated to {args}")

                    elif action == "click":
                        page.click(args)
                        self.action_history.append(("click", args))
                        print(f"✓ Clicked {args}")

                    elif action == "fill":
                        selector, value = args.split("|", 1)
                        page.fill(selector, value)
                        self.action_history.append(("fill", selector, value))
                        print(f"✓ Filled {selector}")

                    elif action == "press":
                        page.keyboard.press(args)
                        self.action_history.append(("press", args))
                        print(f"✓ Pressed {args}")

                    elif action == "wait":
                        ms = int(args)
                        page.wait_for_timeout(ms)
                        self.action_history.append(("wait", ms))
                        print(f"✓ Waited {ms}ms")

                    elif action == "wait_for":
                        page.wait_for_selector(args)
                        self.action_history.append(("wait_for", args))
                        print(f"✓ Element appeared: {args}")

                    elif action == "mark":
                        self.mark(args)

                    elif action == "save":
                        filename = args or f"replay_{self.session_num}.json"
                        self._save_sequence(filename)

                    elif action == "history":
                        print(self.bookmark.summary())

                    elif action == "list":
                        # Already shown in header, just acknowledge
                        print("See command list above ↑")

                    elif action == "quit":
                        break

                    else:
                        print(f"❌ Unknown command: {action}")

                except KeyboardInterrupt:
                    print("\n(Use 'quit' to exit)")
                except Exception as e:
                    print(f"❌ Error: {e}")
                    import traceback
                    traceback.print_exc()

            # Cleanup
            self.mark("Session end")
            context.close()

            print(f"\n{'='*70}")
            print(f"Session saved to: {self.session_dir}")
            print(f"HTTP capture:     {self.burp_xml_path}")
            print(f"Actions:          {self.bookmark_path}")
            print(f"\nNext steps:")
            print(f"  cd {self.session_dir}/output")
            print(f"  python3 ../../src/idor_analyzer.py ../input/history_{self.session_num}.xml")
            print(f"{'='*70}\n")

    def _save_sequence(self, filename: str):
        """Save action sequence for replay."""
        with open(filename, 'w') as f:
            json.dump({
                "session": self.session_num,
                "timestamp": datetime.now().isoformat(),
                "actions": self.action_history
            }, f, indent=2)
        print(f"✓ Saved {len(self.action_history)} actions to {filename}")

    def replay_sequence(self, sequence_file: str):
        """Replay a saved action sequence."""
        with open(sequence_file) as f:
            data = json.load(f)
            sequence = data["actions"]

        print(f"\n{'='*70}")
        print(f"REPLAYING: {sequence_file}")
        print(f"Actions: {len(sequence)}")
        print(f"{'='*70}\n")

        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(
                user_data_dir=self.profile_dir,
                headless=self.headless,
            )

            context.route("**/*", self._route_handler)
            page = context.new_page()

            self.mark("Replay start")

            for i, action_tuple in enumerate(sequence, 1):
                action = action_tuple[0]
                args = action_tuple[1:]

                print(f"[{i}/{len(sequence)}] {action} {args}")

                try:
                    if action == "goto":
                        page.goto(args[0])
                    elif action == "click":
                        page.click(args[0])
                    elif action == "fill":
                        page.fill(args[0], args[1])
                    elif action == "press":
                        page.keyboard.press(args[0])
                    elif action == "wait":
                        page.wait_for_timeout(args[0])
                    elif action == "wait_for":
                        page.wait_for_selector(args[0])

                    # Mark after significant actions
                    if action in ["goto", "click"]:
                        self.mark(f"Replay: {action} {args[0][:50]}")

                except Exception as e:
                    print(f"  ❌ Failed: {e}")
                    choice = input("  Continue? (y/n): ")
                    if choice.lower() != 'y':
                        break

            self.mark("Replay end")
            context.close()

            print(f"\n✓ Replay complete. Captured to {self.burp_xml_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Interactive UI automation with HTTP capture for IDOR analysis"
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="Browser profile directory (e.g., /home/user/pw-profiles/admin)"
    )
    parser.add_argument(
        "--session",
        type=int,
        required=True,
        help="Session number (creates session_N directory)"
    )
    parser.add_argument(
        "--replay",
        help="Replay saved action sequence from JSON file"
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run browser in headless mode"
    )

    args = parser.parse_args()

    automation = UIAutomation(
        profile_dir=args.profile,
        session_num=args.session,
        headless=args.headless
    )

    if args.replay:
        automation.replay_sequence(args.replay)
    else:
        automation.run_interactive()


if __name__ == "__main__":
    main()
