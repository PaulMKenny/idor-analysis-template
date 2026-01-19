"""
ActionBookmark - Tracks action boundaries in UI automation sessions.

Provides sequential action IDs that can be correlated with HTTP requests
captured during browser automation.
"""

import json
import os
from datetime import datetime
from typing import Optional, Dict, List


class ActionBookmark:
    """
    Manages action IDs and metadata for UI automation sessions.

    Each mark() creates a new action boundary, returning a sequential ID.
    HTTP requests captured after a mark() are associated with that action ID.
    """

    def __init__(self, session_file: Optional[str] = None):
        """
        Initialize action bookmark tracker.

        Args:
            session_file: Optional JSON file to persist action history
        """
        self.current_id = 0
        self.actions: List[Dict] = []
        self.session_file = session_file

        if session_file and os.path.exists(session_file):
            self._load_session()

    def mark(self, description: str, metadata: Optional[Dict] = None) -> int:
        """
        Mark a new action boundary.

        Args:
            description: Human-readable action name (e.g., "Open user list")
            metadata: Optional dict of additional context

        Returns:
            int: New action ID
        """
        self.current_id += 1

        action = {
            "id": self.current_id,
            "description": description,
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {}
        }

        self.actions.append(action)
        print(f"[ACTION {self.current_id}] {description}")

        if self.session_file:
            self._save_session()

        return self.current_id

    def get_current_id(self) -> int:
        """Get the current action ID without creating a new one."""
        return self.current_id

    def get_action(self, action_id: int) -> Optional[Dict]:
        """Retrieve action metadata by ID."""
        for action in self.actions:
            if action["id"] == action_id:
                return action
        return None

    def list_actions(self) -> List[Dict]:
        """Get all recorded actions."""
        return self.actions.copy()

    def summary(self) -> str:
        """Generate human-readable summary of all actions."""
        lines = [f"\n{'='*60}", "ACTION SUMMARY", f"{'='*60}"]

        for action in self.actions:
            lines.append(
                f"[{action['id']:3d}] {action['timestamp'][:19]} - {action['description']}"
            )
            if action['metadata']:
                for key, value in action['metadata'].items():
                    lines.append(f"      {key}: {value}")

        lines.append(f"{'='*60}\n")
        return "\n".join(lines)

    def _save_session(self):
        """Persist action history to JSON file."""
        with open(self.session_file, 'w') as f:
            json.dump({
                "current_id": self.current_id,
                "actions": self.actions
            }, f, indent=2)

    def _load_session(self):
        """Load action history from JSON file."""
        with open(self.session_file) as f:
            data = json.load(f)
            self.current_id = data.get("current_id", 0)
            self.actions = data.get("actions", [])


if __name__ == "__main__":
    # Example usage
    bm = ActionBookmark("test_session.json")

    bm.mark("Open dashboard", {"url": "https://example.com/dashboard"})
    bm.mark("Navigate to users")
    bm.mark("Select user #123", {"user_id": 123})

    print(bm.summary())
