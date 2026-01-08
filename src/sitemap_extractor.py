#!/usr/bin/env python3
"""
Sitemap Extractor — Normalized Endpoint Tree

Purpose:
- Consume Burp sitemap XML
- Normalize path identifiers into {id}
- Provide endpoint structure awareness

Non-goals:
- Authorization inference
- IDOR detection
"""

import sys
import re
from collections import defaultdict
from urllib.parse import urlparse
from lxml import etree

PATH_ID_RE = re.compile(
    r'^([0-9]+|[a-f0-9-]{8,}|[A-Za-z0-9_-]{16,})$',
    re.I
)

def normalize_path(path: str) -> list[str]:
    parts = [p for p in path.split("/") if p]
    normalized = []
    for p in parts:
        if PATH_ID_RE.match(p):
            normalized.append("{id}")
        else:
            normalized.append(p)
    return normalized

def build_tree(xml_path: str):
    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse(xml_path, parser)
    root = tree.getroot()

    fs = defaultdict(dict)

    for item in root.findall(".//item"):
        url_elem = item.find("url")
        if url_elem is None or not url_elem.text:
            continue

        parsed = urlparse(url_elem.text)
        host = parsed.hostname
        if not host:
            continue

        parts = normalize_path(parsed.path)

        cursor = fs[host]
        for part in parts:
            cursor = cursor.setdefault(part, {})

    return fs

def print_tree(tree: dict, indent: str = ""):
    items = sorted(tree.items())
    for i, (name, subtree) in enumerate(items):
        last = i == len(items) - 1
        prefix = "└── " if last else "├── "
        print(indent + prefix + name)
        if subtree:
            print_tree(subtree, indent + ("    " if last else "│   "))

def main():
    if len(sys.argv) != 2:
        print("Usage: sitemap_extractor.py <sitemap.xml>")
        sys.exit(1)

    sitemap = sys.argv[1]
    tree = build_tree(sitemap)

    for host, subtree in tree.items():
        print(host + "/")
        print_tree(subtree, "│   ")

if __name__ == "__main__":
    main()