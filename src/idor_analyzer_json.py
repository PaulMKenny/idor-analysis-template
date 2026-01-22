#!/usr/bin/env python3
"""
IDOR Analyzer - JSON Direct Input
Analyzes Playwright recordings for IDOR vulnerabilities without XML conversion
"""

import sys
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any, Set
import re

# Import the Playwright JSON parser
from playwright_json_parser import PlaywrightRecording


def extract_numeric_ids(text: str) -> Set[str]:
    """Extract potential numeric IDs from text"""
    # Match standalone numbers (likely IDs)
    patterns = [
        r'/(\d{3,})',  # Path segments with 3+ digits
        r'[?&]id=(\d+)',  # Query param id=123
        r'[?&]user_?id=(\d+)',  # user_id=123
        r'[?&]account_?id=(\d+)',  # account_id=123
        r'"id"\s*:\s*(\d+)',  # JSON: "id": 123
        r'"user_?id"\s*:\s*(\d+)',  # JSON: "userId": 123
    ]

    ids = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        ids.update(matches)

    return ids


def extract_uuid_like(text: str) -> Set[str]:
    """Extract UUID-like strings"""
    # UUID pattern
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    matches = re.findall(uuid_pattern, text, re.IGNORECASE)
    return set(matches)


def extract_tokens(text: str) -> Set[str]:
    """Extract potential auth tokens"""
    patterns = [
        r'[Bb]earer\s+([A-Za-z0-9_\-\.]+)',
        r'[Tt]oken["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]+)',
        r'session["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]+)',
    ]

    tokens = set()
    for pattern in patterns:
        matches = re.findall(pattern, text)
        tokens.update(matches)

    return tokens


def analyze_request_for_idor(request: Dict[str, Any], user: str) -> Dict[str, Any]:
    """Analyze a single request for potential IDOR indicators"""

    url = request.get('url', '')
    method = request.get('method', 'GET')
    post_data = request.get('postData', '')
    response_body = request.get('responseBody', '')
    status = request.get('status', 0)

    # Parse URL
    parsed = urlparse(url)
    path = parsed.path
    query = parsed.query

    # Extract IDs from URL
    url_ids = extract_numeric_ids(url)
    url_uuids = extract_uuid_like(url)

    # Extract IDs from POST data
    post_ids = extract_numeric_ids(post_data) if post_data else set()
    post_uuids = extract_uuid_like(post_data) if post_data else set()

    # Extract IDs from response
    response_ids = extract_numeric_ids(response_body) if response_body else set()
    response_uuids = extract_uuid_like(response_body) if response_body else set()

    # Detect potential IDOR patterns
    idor_indicators = []

    # Pattern 1: Numeric ID in path
    if url_ids:
        idor_indicators.append({
            'type': 'numeric_id_in_path',
            'severity': 'high',
            'ids': list(url_ids),
            'description': f'URL contains numeric IDs that may be enumerable'
        })

    # Pattern 2: UUID in path (still testable)
    if url_uuids:
        idor_indicators.append({
            'type': 'uuid_in_path',
            'severity': 'medium',
            'ids': list(url_uuids),
            'description': f'URL contains UUIDs (test with other user UUIDs)'
        })

    # Pattern 3: ID in POST data
    if post_ids or post_uuids:
        idor_indicators.append({
            'type': 'id_in_request_body',
            'severity': 'high',
            'ids': list(post_ids.union(post_uuids)),
            'description': f'Request body contains IDs that may reference other users'
        })

    # Pattern 4: Successful response with other user data
    if status == 200 and (response_ids or response_uuids):
        idor_indicators.append({
            'type': 'user_data_in_response',
            'severity': 'info',
            'ids': list(response_ids.union(response_uuids)),
            'description': f'Response contains user/resource IDs'
        })

    # Pattern 5: Common IDOR-prone endpoints
    idor_prone_patterns = [
        r'/users?/\d+',
        r'/accounts?/\d+',
        r'/profiles?/\d+',
        r'/api/v\d+/user',
        r'/api/v\d+/account',
        r'/dashboard',
        r'/settings',
    ]

    for pattern in idor_prone_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            idor_indicators.append({
                'type': 'idor_prone_endpoint',
                'severity': 'high',
                'pattern': pattern,
                'description': f'Endpoint matches common IDOR-vulnerable pattern'
            })
            break

    return {
        'url': url,
        'method': method,
        'status': status,
        'action': request.get('action', ''),
        'user': user,
        'idor_indicators': idor_indicators,
        'extracted_ids': {
            'url_numeric': list(url_ids),
            'url_uuid': list(url_uuids),
            'post_numeric': list(post_ids),
            'post_uuid': list(post_uuids),
            'response_numeric': list(response_ids),
            'response_uuid': list(response_uuids),
        }
    }


def analyze_recording(recording: PlaywrightRecording) -> Dict[str, Any]:
    """Analyze entire recording for IDOR vulnerabilities"""

    all_requests = recording.get_all_requests()

    analyzed_requests = []
    high_severity_findings = []
    medium_severity_findings = []

    for request in all_requests:
        analysis = analyze_request_for_idor(request, recording.user)
        analyzed_requests.append(analysis)

        # Categorize findings
        for indicator in analysis['idor_indicators']:
            if indicator['severity'] == 'high':
                high_severity_findings.append({
                    'url': analysis['url'],
                    'method': analysis['method'],
                    'action': analysis['action'],
                    'indicator': indicator
                })
            elif indicator['severity'] == 'medium':
                medium_severity_findings.append({
                    'url': analysis['url'],
                    'method': analysis['method'],
                    'action': analysis['action'],
                    'indicator': indicator
                })

    summary = recording.get_summary()

    return {
        'summary': summary,
        'analyzed_requests': analyzed_requests,
        'findings': {
            'high': high_severity_findings,
            'medium': medium_severity_findings,
            'total': len(high_severity_findings) + len(medium_severity_findings)
        }
    }


def print_analysis_report(analysis: Dict[str, Any]):
    """Print human-readable analysis report"""

    summary = analysis['summary']
    findings = analysis['findings']

    print("=" * 70)
    print("IDOR ANALYSIS REPORT (Playwright Recording)")
    print("=" * 70)
    print(f"\nUser: {summary['user']}")
    print(f"Sequence: {summary['sequenceId']}")
    print(f"Timestamp: {summary['timestamp']}")
    print(f"\nActions: {summary['totalActions']}")
    print(f"Requests: {summary['totalRequests']}")

    if summary.get('validation'):
        val = summary['validation']
        print(f"Validation: ✓ (Actions: {val.get('totalActions')}, Requests: {val.get('totalRequests')})")

    print("\n" + "=" * 70)
    print(f"FINDINGS SUMMARY")
    print("=" * 70)
    print(f"High Severity: {len(findings['high'])}")
    print(f"Medium Severity: {len(findings['medium'])}")
    print(f"Total: {findings['total']}")

    if findings['high']:
        print("\n" + "=" * 70)
        print("HIGH SEVERITY FINDINGS")
        print("=" * 70)

        for i, finding in enumerate(findings['high'], 1):
            print(f"\n[{i}] {finding['method']} {finding['url']}")
            print(f"    Action: {finding['action']}")
            print(f"    Type: {finding['indicator']['type']}")
            print(f"    Description: {finding['indicator']['description']}")

            if 'ids' in finding['indicator']:
                print(f"    IDs found: {', '.join(finding['indicator']['ids'][:5])}")
            if 'pattern' in finding['indicator']:
                print(f"    Matched pattern: {finding['indicator']['pattern']}")

    if findings['medium']:
        print("\n" + "=" * 70)
        print("MEDIUM SEVERITY FINDINGS")
        print("=" * 70)

        for i, finding in enumerate(findings['medium'], 1):
            print(f"\n[{i}] {finding['method']} {finding['url']}")
            print(f"    Action: {finding['action']}")
            print(f"    Type: {finding['indicator']['type']}")
            print(f"    Description: {finding['indicator']['description']}")

    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)

    if findings['total'] > 0:
        print("\n1. Test each finding with a different user account")
        print("2. Replace user-specific IDs with other user IDs")
        print("3. Verify proper authorization checks are in place")
        print("4. Use generated test scripts for automated multi-user testing")
    else:
        print("\nNo obvious IDOR indicators detected.")
        print("However, manual testing with multiple users is still recommended.")

    print("\n" + "=" * 70)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 idor_analyzer_json.py <recording.json>")
        sys.exit(1)

    recording_path = sys.argv[1]

    try:
        print(f"Loading recording: {recording_path}\n")
        recording = PlaywrightRecording(recording_path)

        print("Analyzing requests for IDOR vulnerabilities...\n")
        analysis = analyze_recording(recording)

        print_analysis_report(analysis)

        # Save detailed JSON report
        output_file = Path("idor_analysis_detailed.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2)

        print(f"\nDetailed JSON report saved: {output_file}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
