#!/usr/bin/env python3
# ==================================================
# RAW HTTP HISTORY DUMPER (TEXT ONLY)
# ==================================================
# Purpose:
#   Dump raw HTTP request + response pairs from a Burp XML
#   exactly as captured, in chronological order.
# ==================================================

import sys
import base64
import xml.etree.ElementTree as ET
from pathlib import Path

def decode_http(elem):
    if elem is None or elem.text is None:
        return ""
    try:
        return base64.b64decode(elem.text).decode(errors="replace")
    except Exception:
        return ""

def iter_http_messages(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for idx, item in enumerate(root.findall("item"), start=1):
        req = decode_http(item.find("request"))
        resp = decode_http(item.find("response"))
        yield idx, req, resp

def main():
    if len(sys.argv) != 2:
        print("Usage: raw_http_dump.py <history.xml>")
        sys.exit(1)

    xml_path = Path(sys.argv[1])

    if not xml_path.is_file():
        print(f"ERROR: File not found: {xml_path}")
        sys.exit(1)

    print(f"[*] Dumping raw HTTP history from: {xml_path}\n")

    for msg_id, request, response in iter_http_messages(xml_path):
        print("=" * 80)
        print(f"MSG {msg_id}")
        print("=" * 80)

        print("\n--- REQUEST ---\n")
        print(request.strip() if request else "(empty)")

        print("\n--- RESPONSE ---\n")
        print(response.strip() if response else "(empty)")
        print("\n")

if __name__ == "__main__":
    main()
