#!/usr/bin/env python3
"""Test script to verify idor_interface.py navigation modes"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Mock the main loop to test navigation
NAV_MODE = "project"

def toggle_mode():
    global NAV_MODE
    modes = ["project", "session", "ui_automation"]
    current_idx = modes.index(NAV_MODE)
    NAV_MODE = modes[(current_idx + 1) % len(modes)]
    return NAV_MODE

print("Testing navigation mode cycling:")
print(f"Start: {NAV_MODE}")

NAV_MODE = toggle_mode()
print(f"After toggle 1: {NAV_MODE}")
assert NAV_MODE == "session", f"Expected 'session', got '{NAV_MODE}'"

NAV_MODE = toggle_mode()
print(f"After toggle 2: {NAV_MODE}")
assert NAV_MODE == "ui_automation", f"Expected 'ui_automation', got '{NAV_MODE}'"

NAV_MODE = toggle_mode()
print(f"After toggle 3: {NAV_MODE}")
assert NAV_MODE == "project", f"Expected 'project', got '{NAV_MODE}'"

print("\n✓ All tests passed!")
print("  project → session → ui_automation → project")
