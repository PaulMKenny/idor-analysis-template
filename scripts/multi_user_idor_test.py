#!/usr/bin/env python3
"""
Multi-User IDOR Testing Workflow

Runs the same action sequence with different user profiles to identify
authorization issues through differential analysis.

Workflow:
1. Record actions with admin/high-privilege user
2. Replay same actions with low-privilege users
3. Compare captured HTTP traffic and responses
4. Run idor_analyzer on each session
5. Generate comparison report

Usage:
    # Step 1: Record baseline with admin
    python ui_automation.py --profile /path/to/admin --session 1
    [Interactive session - perform actions]
    save baseline_actions.json
    quit

    # Step 2: Replay with multiple users
    python multi_user_idor_test.py baseline_actions.json --profiles profiles.json

    # profiles.json format:
    {
        "admin": "/path/to/admin-profile",
        "user_a": "/path/to/user_a-profile",
        "user_b": "/path/to/user_b-profile"
    }
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from ui_automation import UIAutomation


class MultiUserIDORTest:
    """
    Orchestrates multi-user IDOR testing campaigns.
    """

    def __init__(self, action_sequence: str, profiles: Dict[str, str], base_session: int = 100):
        self.action_sequence = action_sequence
        self.profiles = profiles
        self.base_session = base_session
        self.session_map: Dict[str, int] = {}

    def run_all_profiles(self, headless: bool = True):
        """Run action sequence for each user profile."""
        print(f"""
{'='*70}
MULTI-USER IDOR TESTING
{'='*70}
Action sequence: {self.action_sequence}
Profiles:        {len(self.profiles)}
Starting session: {self.base_session}
{'='*70}
""")

        for i, (profile_name, profile_dir) in enumerate(self.profiles.items()):
            session_num = self.base_session + i
            self.session_map[profile_name] = session_num

            print(f"\n{'='*70}")
            print(f"[{i+1}/{len(self.profiles)}] Running as: {profile_name}")
            print(f"Profile:  {profile_dir}")
            print(f"Session:  {session_num}")
            print(f"{'='*70}\n")

            try:
                automation = UIAutomation(
                    profile_dir=profile_dir,
                    session_num=session_num,
                    headless=headless
                )
                automation.replay_sequence(self.action_sequence)

                print(f"✓ {profile_name} session complete")

            except Exception as e:
                print(f"❌ {profile_name} failed: {e}")
                import traceback
                traceback.print_exc()

        print(f"\n{'='*70}")
        print(f"ALL PROFILES COMPLETE")
        print(f"{'='*70}")
        self._print_session_summary()

    def run_analyzers(self):
        """Run idor_analyzer.py on all captured sessions."""
        print(f"\n{'='*70}")
        print(f"RUNNING IDOR ANALYSIS")
        print(f"{'='*70}\n")

        analyzer_path = Path(__file__).parent.parent / "src" / "idor_analyzer.py"

        for profile_name, session_num in self.session_map.items():
            session_dir = Path(f"sessions/session_{session_num}")
            input_xml = session_dir / "input" / f"history_{session_num}.xml"
            output_dir = session_dir / "output"

            if not input_xml.exists():
                print(f"❌ {profile_name}: No input file {input_xml}")
                continue

            print(f"[{profile_name}] Analyzing session {session_num}...")

            try:
                # Run analyzer
                result = subprocess.run(
                    ["python3", str(analyzer_path), str(input_xml)],
                    cwd=str(output_dir),
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )

                if result.returncode == 0:
                    print(f"  ✓ Analysis complete")
                    # Show brief summary
                    csv_file = output_dir / f"history_{session_num}_idor_candidates.csv"
                    if csv_file.exists():
                        with open(csv_file) as f:
                            lines = f.readlines()
                            print(f"  → {len(lines)-1} IDOR candidates found")
                else:
                    print(f"  ❌ Analyzer failed:")
                    print(result.stderr[:500])

            except subprocess.TimeoutExpired:
                print(f"  ❌ Analyzer timed out")
            except Exception as e:
                print(f"  ❌ Error: {e}")

        print(f"\n{'='*70}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*70}")
        self._print_analysis_summary()

    def generate_comparison_report(self, output_file: str = "idor_comparison.txt"):
        """
        Generate differential report comparing IDOR candidates across users.

        Shows which IDs/endpoints are accessible by which users.
        """
        print(f"\n{'='*70}")
        print(f"GENERATING COMPARISON REPORT")
        print(f"{'='*70}\n")

        # Collect all candidates per profile
        profile_candidates: Dict[str, List[Dict]] = {}

        for profile_name, session_num in self.session_map.items():
            csv_file = Path(f"sessions/session_{session_num}/output/history_{session_num}_idor_candidates.csv")

            if not csv_file.exists():
                print(f"⚠ {profile_name}: No candidates file")
                continue

            import csv
            with open(csv_file) as f:
                reader = csv.DictReader(f)
                candidates = list(reader)
                profile_candidates[profile_name] = candidates

            print(f"✓ {profile_name}: {len(candidates)} candidates")

        # Build comparison matrix
        report_lines = [
            "="*70,
            "IDOR DIFFERENTIAL ANALYSIS",
            "="*70,
            "",
            f"Compared profiles: {', '.join(self.profiles.keys())}",
            f"Sessions: {', '.join(str(s) for s in self.session_map.values())}",
            "",
            "="*70,
            "HIGH-PRIORITY CROSS-USER ANALYSIS",
            "="*70,
            ""
        ]

        # Find IDs that appear in multiple profiles (potential IDOR)
        all_id_keys = set()
        for candidates in profile_candidates.values():
            for c in candidates:
                id_val = c.get("id_value", "")
                key = c.get("key", "")
                endpoint = c.get("endpoint", "")
                all_id_keys.add((id_val, key, endpoint))

        # Group by ID/endpoint
        for id_val, key, endpoint in sorted(all_id_keys):
            profiles_with_id = []

            for profile_name, candidates in profile_candidates.items():
                for c in candidates:
                    if (c.get("id_value") == id_val and
                        c.get("key") == key and
                        c.get("endpoint") == endpoint):
                        score = c.get("score", "0")
                        tier = c.get("tier", "?")
                        profiles_with_id.append((profile_name, score, tier))
                        break

            # Only report if multiple profiles can access
            if len(profiles_with_id) > 1:
                report_lines.append(f"\n📍 {key}={id_val} @ {endpoint}")
                report_lines.append(f"   Accessible by {len(profiles_with_id)} profiles:")

                for pname, score, tier in profiles_with_id:
                    report_lines.append(f"     - {pname:15s} [Score: {score:>3s}, Tier: {tier}]")

                # IDOR risk assessment
                profile_types = [p for p in profiles_with_id]
                if any("admin" in p[0].lower() for p in profile_types) and any("user" in p[0].lower() for p in profile_types):
                    report_lines.append("     ⚠️  POTENTIAL IDOR: Admin and regular user both access this ID")

        # Per-profile unique candidates
        report_lines.extend([
            "",
            "="*70,
            "PROFILE-SPECIFIC CANDIDATES",
            "="*70,
            ""
        ])

        for profile_name, candidates in profile_candidates.items():
            tier1 = [c for c in candidates if c.get("tier") == "1"]
            report_lines.append(f"\n{profile_name}: {len(tier1)} Tier-1 candidates")

            # Show top 10
            for c in sorted(tier1, key=lambda x: -int(x.get("score", "0")))[:10]:
                score = c.get("score", "0")
                key = c.get("key", "")
                id_val = c.get("id_value", "")
                endpoint = c.get("endpoint", "")[:50]
                report_lines.append(f"  [{score:>3s}] {key}={id_val} @ {endpoint}")

        # Write report
        report_lines.append("\n" + "="*70 + "\n")

        with open(output_file, 'w') as f:
            f.write("\n".join(report_lines))

        print(f"\n✓ Comparison report written to: {output_file}")
        print("\nKey findings:")

        # Count potential IDORs
        idor_lines = [l for l in report_lines if "POTENTIAL IDOR" in l]
        print(f"  - {len(idor_lines)} potential IDOR vulnerabilities detected")
        print(f"  - Review {output_file} for detailed analysis")

    def _print_session_summary(self):
        """Print summary of created sessions."""
        print("\nCreated sessions:")
        for profile_name, session_num in self.session_map.items():
            session_dir = Path(f"sessions/session_{session_num}")
            print(f"  {profile_name:15s} → session_{session_num:3d}  ({session_dir})")

    def _print_analysis_summary(self):
        """Print summary of analysis outputs."""
        print("\nAnalysis outputs:")
        for profile_name, session_num in self.session_map.items():
            output_dir = Path(f"sessions/session_{session_num}/output")
            csv_file = output_dir / f"history_{session_num}_idor_candidates.csv"

            if csv_file.exists():
                print(f"  {profile_name:15s} → {csv_file}")
            else:
                print(f"  {profile_name:15s} → (no output)")


def main():
    parser = argparse.ArgumentParser(
        description="Multi-user IDOR testing workflow"
    )
    parser.add_argument(
        "action_sequence",
        help="JSON file with recorded action sequence"
    )
    parser.add_argument(
        "--profiles",
        required=True,
        help="JSON file mapping profile names to directories"
    )
    parser.add_argument(
        "--base-session",
        type=int,
        default=100,
        help="Starting session number (default: 100)"
    )
    parser.add_argument(
        "--skip-replay",
        action="store_true",
        help="Skip replay, only run analysis on existing sessions"
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip analysis, only do replay"
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate comparison report from existing results"
    )
    parser.add_argument(
        "--visible",
        action="store_true",
        help="Show browser UI (not headless)"
    )

    args = parser.parse_args()

    # Load profiles
    with open(args.profiles) as f:
        profiles = json.load(f)

    # Validate profile directories
    for name, path in profiles.items():
        if not os.path.exists(path):
            print(f"❌ Profile directory not found: {name} → {path}")
            sys.exit(1)

    # Run workflow
    tester = MultiUserIDORTest(
        action_sequence=args.action_sequence,
        profiles=profiles,
        base_session=args.base_session
    )

    if args.report_only:
        # Just generate report from existing results
        tester.session_map = {
            name: args.base_session + i
            for i, name in enumerate(profiles.keys())
        }
        tester.generate_comparison_report()
    else:
        # Full workflow
        if not args.skip_replay:
            tester.run_all_profiles(headless=not args.visible)

        if not args.skip_analysis:
            tester.run_analyzers()

        tester.generate_comparison_report()

    print(f"\n{'='*70}")
    print("WORKFLOW COMPLETE")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
