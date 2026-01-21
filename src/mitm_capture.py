#!/usr/bin/env python3
"""
mitmproxy addon for UI automation traffic capture

Captures raw HTTP traffic partitioned by:
  User → UI Session → UI Action

Action boundaries are declared explicitly via marker requests from Playwright.
The marker request pattern ensures clean separation between control signals
and captured traffic.
"""

from mitmproxy import http
from pathlib import Path
import json
import time
from datetime import datetime


def iso_ts(ts=None):
    """UTC ISO-8601 timestamp with milliseconds"""
    return (
        datetime.utcfromtimestamp(ts) if ts is not None else datetime.utcnow()
    ).isoformat(timespec="milliseconds") + "Z"


class PlaywrightCapture:
    """
    mitmproxy addon that captures raw HTTP traffic partitioned by:
    User → UI Session → UI Action

    Action boundaries are declared explicitly via a marker request.
    """

    ACTION_MARKER_PATH = "/__ui_action_marker__"

    def __init__(self):
        self.current_user = None
        self.current_session = None
        self.current_action = None
        self.action_start_time = None

        self.transactions = []
        self.seq_counter = 0

        self.base_dir = Path("ui-automation/recordings")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    # ----------------------------
    # Action boundary handling
    # ----------------------------
    def _start_action(self, user: str, session_id: str, action_name: str):
        """Internal: flush previous action and start new one"""
        # Flush previous action
        if self.current_action:
            self.save_partition()

        self.current_user = user
        self.current_session = session_id
        self.current_action = action_name
        self.action_start_time = time.time()

        self.transactions = []
        self.seq_counter = 0

        print(
            f"[mitmproxy] action start → "
            f"{user}/{session_id}/{action_name}"
        )

    # ----------------------------
    # Marker request handler (responds to prevent browser errors)
    # ----------------------------
    def request(self, flow: http.HTTPFlow):
        """Handle action marker requests from Playwright"""
        if flow.request.path == self.ACTION_MARKER_PATH:
            user = flow.request.headers.get("X-Test-User")
            session = flow.request.headers.get("X-UI-Session")
            action = flow.request.headers.get("X-UI-Action")

            if user and session and action:
                self._start_action(user, session, action)

                # Respond immediately to prevent browser console errors
                flow.response = http.Response.make(
                    200,
                    json.dumps({"status": "action_started", "action": action}).encode(),
                    {"Content-Type": "application/json"}
                )
            else:
                # Missing required headers
                flow.response = http.Response.make(
                    400,
                    json.dumps({
                        "error": "missing required headers",
                        "required": ["X-Test-User", "X-UI-Session", "X-UI-Action"]
                    }).encode(),
                    {"Content-Type": "application/json"}
                )

    # ----------------------------
    # Core capture hook
    # ----------------------------
    def response(self, flow: http.HTTPFlow):
        """Capture completed HTTP transactions"""
        if not flow.response:
            return

        # Ignore marker requests (already handled in request())
        if flow.request.path == self.ACTION_MARKER_PATH:
            return

        # Ignore traffic until an action is declared
        if not self.current_action:
            return

        self.seq_counter += 1

        transaction = {
            "seq": self.seq_counter,
            "timestamp": iso_ts(),
            "request": {
                "method": flow.request.method,
                "url": flow.request.url,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "body": flow.request.text if flow.request.content else None,
                "body_size": len(flow.request.content) if flow.request.content else 0,
            },
            "response": {
                "status": flow.response.status_code,
                "reason": flow.response.reason,
                "headers": dict(flow.response.headers),
                "body": flow.response.text if flow.response.content else None,
                "body_size": len(flow.response.content) if flow.response.content else 0,
            },
            "timing": {
                "request_start": iso_ts(flow.request.timestamp_start),
                "response_end": iso_ts(flow.response.timestamp_end),
                "duration_ms": int(
                    (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
                ),
            },
        }

        self.transactions.append(transaction)

    # ----------------------------
    # Persist one action partition
    # ----------------------------
    def save_partition(self):
        """Save current action partition to disk"""
        if not self.transactions:
            return

        partition = {
            "meta": {
                "user": self.current_user,
                "session_id": self.current_session,
                "action_name": self.current_action,
                "action_start_time": iso_ts(self.action_start_time),
                "action_end_time": iso_ts(),
                "total_requests": len(self.transactions),
                "capture_source": "mitmproxy",
            },
            "transactions": self.transactions,
        }

        # Directory: ui-automation/recordings/<user>/<session>/
        user_dir = self.base_dir / self.current_user
        session_dir = user_dir / self.current_session
        session_dir.mkdir(parents=True, exist_ok=True)

        action_safe = (
            self.current_action
            .replace(" ", "_")
            .replace("/", "_")
            .lower()
        )

        # Preserve multiple runs with millisecond timestamps
        timestamp = int(time.time() * 1000)
        filename = f"{action_safe}-{timestamp}.json"
        filepath = session_dir / filename

        filepath.write_text(json.dumps(partition, indent=2))

        print(
            f"[mitmproxy] saved partition → "
            f"{self.current_user}/{self.current_session}/{filename}"
        )

    # ----------------------------
    # Ensure final flush on shutdown
    # ----------------------------
    def done(self):
        """Called when mitmproxy shuts down - flush any pending action"""
        if self.current_action:
            self.save_partition()


addons = [PlaywrightCapture()]
