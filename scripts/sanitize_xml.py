#!/usr/bin/env python3
"""
Strip cookies, authorization headers, and tokens from Burp XML exports.
"""
import re, sys
data = sys.stdin.read()
data = re.sub(r'(Authorization:).*', r'\1 REDACTED', data, flags=re.I)
data = re.sub(r'(Cookie:).*', r'\1 REDACTED', data, flags=re.I)
print(data)
