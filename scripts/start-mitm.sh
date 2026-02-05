#!/bin/bash
# Quick start script for mitmproxy with UI automation capture

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "=== Starting mitmproxy for UI Automation ==="
echo ""
echo "Addon: src/mitm_capture.py"
echo "Port: 8080"
echo "Output: ui-automation/recordings/"
echo ""
echo "Press Ctrl+C to stop"
echo ""

mitmdump -s src/mitm_capture.py --listen-port 8080
