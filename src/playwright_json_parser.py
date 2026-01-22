#!/usr/bin/env python3
"""
Playwright JSON Parser for IDOR Analysis
Converts Playwright recording JSON to analyzable format (lossless)
"""

import json
import base64
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs


class PlaywrightRecording:
    """Represents a Playwright recording with HTTP requests"""

    def __init__(self, recording_path: str):
        with open(recording_path, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

        self.user = self.data.get('user', 'unknown')
        self.sequence_id = self.data.get('sequenceId', 'unknown')
        self.timestamp = self.data.get('timestamp', '')
        self.buckets = self.data.get('buckets', [])
        self.validation = self.data.get('validation', {})

    def get_all_requests(self) -> List[Dict[str, Any]]:
        """Extract all HTTP requests from all action buckets"""
        requests = []

        for bucket in self.buckets:
            action = bucket.get('action', '')
            bucket_requests = bucket.get('requests', [])

            for req in bucket_requests:
                requests.append({
                    'action': action,
                    'method': req.get('method', 'GET'),
                    'url': req.get('url', ''),
                    'headers': req.get('headers', {}),
                    'postData': req.get('postData', ''),
                    'status': req.get('status', 0),
                    'responseHeaders': req.get('responseHeaders', {}),
                    'responseBody': req.get('responseBody', ''),
                })

        return requests

    def get_requests_by_action(self, action_index: int) -> List[Dict[str, Any]]:
        """Get requests for a specific action bucket"""
        if action_index < 0 or action_index >= len(self.buckets):
            return []

        bucket = self.buckets[action_index]
        return bucket.get('requests', [])

    def extract_urls(self) -> List[str]:
        """Extract all unique URLs"""
        urls = set()
        for req in self.get_all_requests():
            urls.add(req['url'])
        return sorted(urls)

    def extract_parameters(self) -> Dict[str, set]:
        """Extract all query parameters and POST parameters"""
        query_params = {}
        post_params = {}

        for req in self.get_all_requests():
            # Query parameters
            parsed = urlparse(req['url'])
            if parsed.query:
                params = parse_qs(parsed.query)
                for key, values in params.items():
                    if key not in query_params:
                        query_params[key] = set()
                    query_params[key].update(values)

            # POST parameters (if JSON or form data)
            post_data = req.get('postData', '')
            if post_data:
                try:
                    # Try JSON
                    data = json.loads(post_data)
                    if isinstance(data, dict):
                        for key, value in data.items():
                            if key not in post_params:
                                post_params[key] = set()
                            post_params[key].add(str(value))
                except json.JSONDecodeError:
                    # Try form data
                    try:
                        params = parse_qs(post_data)
                        for key, values in params.items():
                            if key not in post_params:
                                post_params[key] = set()
                            post_params[key].update(values)
                    except:
                        pass

        return {
            'query': query_params,
            'post': post_params
        }

    def to_http_archive(self) -> Dict[str, Any]:
        """Convert to HAR-like format for analysis"""
        entries = []

        for req in self.get_all_requests():
            entry = {
                'action': req['action'],
                'request': {
                    'method': req['method'],
                    'url': req['url'],
                    'headers': [{'name': k, 'value': v} for k, v in req['headers'].items()],
                    'postData': req['postData']
                },
                'response': {
                    'status': req['status'],
                    'headers': [{'name': k, 'value': v} for k, v in req['responseHeaders'].items()],
                    'content': {
                        'text': req['responseBody']
                    }
                }
            }
            entries.append(entry)

        return {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'Playwright Recorder',
                    'version': '1.0'
                },
                'entries': entries,
                'metadata': {
                    'user': self.user,
                    'sequenceId': self.sequence_id,
                    'timestamp': self.timestamp,
                    'validation': self.validation
                }
            }
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get recording summary"""
        total_requests = sum(len(b.get('requests', [])) for b in self.buckets)

        return {
            'user': self.user,
            'sequenceId': self.sequence_id,
            'timestamp': self.timestamp,
            'totalActions': len(self.buckets),
            'totalRequests': total_requests,
            'validation': self.validation,
            'actions': [
                {
                    'name': b.get('action', ''),
                    'requestCount': len(b.get('requests', [])),
                    'timeStart': b.get('t_start_sec', 0)
                }
                for b in self.buckets
            ]
        }


def load_recording(recording_path: str) -> PlaywrightRecording:
    """Load a Playwright recording from JSON file"""
    return PlaywrightRecording(recording_path)


def main():
    """CLI interface for testing"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 playwright_json_parser.py <recording.json>")
        print("\nOptions:")
        print("  --summary     Show recording summary")
        print("  --urls        List all URLs")
        print("  --params      Show all parameters")
        print("  --har         Convert to HAR format")
        sys.exit(1)

    recording_path = sys.argv[1]
    recording = load_recording(recording_path)

    mode = sys.argv[2] if len(sys.argv) > 2 else '--summary'

    if mode == '--summary':
        summary = recording.get_summary()
        print(json.dumps(summary, indent=2))

    elif mode == '--urls':
        urls = recording.extract_urls()
        for url in urls:
            print(url)

    elif mode == '--params':
        params = recording.extract_parameters()
        print("=== Query Parameters ===")
        for key, values in params['query'].items():
            print(f"{key}: {', '.join(values)}")

        print("\n=== POST Parameters ===")
        for key, values in params['post'].items():
            print(f"{key}: {', '.join(values)}")

    elif mode == '--har':
        har = recording.to_http_archive()
        print(json.dumps(har, indent=2))

    elif mode == '--requests':
        requests = recording.get_all_requests()
        print(json.dumps(requests, indent=2))


if __name__ == '__main__':
    main()
