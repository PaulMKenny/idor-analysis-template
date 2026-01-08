#!/usr/bin/env python3
# ==================================================
# IDOR ANALYZER — SINGLE SESSION
# GraphQL + REST + ORIGIN TRACKING (ANALYSIS ONLY)
# ==================================================

"""
CLI usage (REQUIRED by idor_interface.py):

    python3 idor_analyzer.py <history.xml> [sitemap.xml]

Notes:
- sitemap.xml is accepted for interface compatibility
- sitemap is NOT used in analysis (analysis-only build)
"""

import sys
import csv
import base64
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# ============================================================
# CONFIG
# ============================================================

class Config:
    # DISCIPLINED: do NOT expand token/key/node/etc
    KEY_REGEX = re.compile(
        r'(?:^|[^a-zA-Z])(id|.*_id|id_.*|uuid|guid|iid)(?:$|[^a-zA-Z])',
        re.IGNORECASE
    )

    PATH_ID_RE = re.compile(
        r'^([0-9]+|[a-f0-9-]{8,}|[A-Za-z0-9_-]{16,})$',
        re.IGNORECASE
    )

    EMBEDDED_RE = re.compile(
        r'<script[^>]*type=["\']application/(?:json|ld\+json)["\'][^>]*>(.*?)</script>|'
        r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )

    GRAPHQL_ID_PATTERNS = [
        re.compile(r'^gid://([^/]+)/([^/]+)/(\d+)$'),
        re.compile(r'^urn:([^:]+):([^:]+):(\d+)$'),
    ]

    SEMANTIC_ID_KEYS = {
        "user_id",
        "account_id",
        "org_id",
        "organisation_id",
        "agent_id",
        "ticket_id",
        "order_id",
        "id",
        "iid",
    }

    BLACKLIST_VALUES = {"true", "false", "null", "-1", "0", "1"}
    BLACKLIST_ENDPOINTS = {"POST /messenger/web/ping"}

# ============================================================
# XML / HTTP PARSING
# ============================================================

def decode_http(elem):
    return base64.b64decode(elem.text) if elem is not None and elem.text else b""

def iter_http_messages(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for idx, item in enumerate(root.findall("item"), start=1):
        yield idx, decode_http(item.find("request")), decode_http(item.find("response"))

def split_http_message(raw):
    text = raw.decode(errors="replace")
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        return "", {}, b""

    lines = head.splitlines()
    request_line = lines[0] if lines else ""
    headers = {}

    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return request_line, headers, body.encode(errors="replace")

def parse_request_line(request_line):
    parts = request_line.split()
    return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)

def extract_status_code(raw_resp):
    if not raw_resp:
        return None
    try:
        line = raw_resp.decode(errors="replace").splitlines()[0]
        for p in line.split():
            if p.isdigit() and len(p) == 3:
                return int(p)
    except:
        pass
    return None

# ============================================================
# EXTRACTION HELPERS
# ============================================================

def extract_url_params(path):
    if "?" not in path:
        return []
    out = []
    for p in path.split("?", 1)[1].split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            out.append((k, v))
    return out

def extract_path_ids(path):
    base = path.split("?")[0]
    parts = [p for p in base.split("/") if p]
    out = []
    for i, part in enumerate(parts):
        if Config.PATH_ID_RE.match(part):
            key = parts[i - 1] if i > 0 else "<path>"
            out.append((key, part))
    return out

def extract_base_path(path):
    return path.split("?")[0].rstrip("/") or "/"

def extract_json_objects(body):
    s = body.decode(errors="replace").lstrip()
    decoder = json.JSONDecoder()
    objs, i = [], 0
    while i < len(s):
        try:
            obj, end = decoder.raw_decode(s, i)
            objs.append(obj)
            i += end
        except:
            i += 1
    return objs

def walk_json_ids(obj):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if Config.KEY_REGEX.search(k) and isinstance(v, (str, int)):
                hits.append((k, str(v)))
            hits.extend(walk_json_ids(v))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(walk_json_ids(v))
    return hits

def walk_json_with_context(obj, parent_id=None):
    hits = []
    if isinstance(obj, dict):
        current_id = obj.get("id") if isinstance(obj.get("id"), (str, int)) else parent_id
        for k, v in obj.items():
            if Config.KEY_REGEX.search(k) and isinstance(v, (str, int)):
                hits.append((k, str(v), parent_id))
            hits.extend(walk_json_with_context(v, current_id))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(walk_json_with_context(v, parent_id))
    return hits

def is_likely_id_value(value):
    if not value or not isinstance(value, str):
        return False
    if value.lower() in Config.BLACKLIST_VALUES:
        return False
    if value.isdigit() and len(value) >= 3:
        return True
    if re.match(r'^[a-f0-9-]{8,}$', value, re.IGNORECASE):
        return True
    if re.match(r'^[A-Za-z0-9_-]{16,}$', value):
        return True
    for pat in Config.GRAPHQL_ID_PATTERNS:
        if pat.match(value):
            return True
    return False

def is_graphql_request(obj):
    return (
        isinstance(obj, dict)
        and sum(k in obj for k in ("query", "variables", "operationName")) >= 2
    )

# ============================================================
# ANALYZER
# ============================================================

class IDORAnalyzer:
    def __init__(self, xml_path):
        self.xml_path = xml_path

        self.id_index = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        self.id_timeline = defaultdict(list)
        self.id_origin = {}

        self.id_cooccurrence = defaultdict(set)
        self.status_by_msg = {}

        self.graphql_operations = defaultdict(list)
        self.msg_to_operation = {}
        self.id_to_operations = defaultdict(set)

        self.client_supplied_ids = set()
        self.raw_messages = {}

    def analyze(self):
        for msg_id, raw_req, raw_resp in iter_http_messages(self.xml_path):
            self.raw_messages[msg_id] = {
                "request": raw_req.decode(errors="replace"),
                "response": raw_resp.decode(errors="replace"),
            }
            self._process(msg_id, raw_req, raw_resp)

    def _process(self, msg_id, raw_req, raw_resp):
        req_line, _, req_body = split_http_message(raw_req)
        method, path = parse_request_line(req_line)

        status = extract_status_code(raw_resp)
        if status is not None:
            self.status_by_msg[msg_id] = status

        request_ids = []

        if path:
            for k, v in extract_url_params(path):
                self._mark_client(v)
                self._record(v, k, "request", msg_id, method, path)
                request_ids.append((k, v))

            for k, v in extract_path_ids(path):
                self._mark_client(v)
                self._record(v, k, "request", msg_id, method, path)
                request_ids.append((k, v))

        for obj in extract_json_objects(req_body):
            if is_graphql_request(obj):
                op = obj.get("operationName", "unknown")
                self.graphql_operations[op].append(msg_id)
                self.msg_to_operation[msg_id] = op

                for k, v in walk_json_ids(obj.get("variables", {})):
                    self._mark_client(v)
                    if is_likely_id_value(v):
                        self.client_supplied_ids.add(v)
                    self._record(v, k, "request", msg_id, method, path)

                payload = {k: v for k, v in obj.items() if k != "variables"}
                for k, v in walk_json_ids(payload):
                    self._record(v, k, "request", msg_id, method, path)
            else:
                for k, v in walk_json_ids(obj):
                    self._record(v, k, "request", msg_id, method, path)

        _, _, resp_body = split_http_message(raw_resp)
        response_ids = []

        for obj in extract_json_objects(resp_body):
            for k, v, parent in walk_json_with_context(obj):
                self._mark_server(v)
                self._record(v, k, "response", msg_id, method, path)
                response_ids.append((k, v))

                if parent and parent != v:
                    self.id_cooccurrence[f"structural:{parent}"].add(f"{k}:{v}")

                if msg_id in self.msg_to_operation:
                    self.id_to_operations[v].add(self.msg_to_operation[msg_id])

        for rk, rv in request_ids:
            for sk, sv in response_ids:
                if rv != sv and is_likely_id_value(sv):
                    self.id_cooccurrence[f"replay:{rk}:{rv}"].add(f"{sk}:{sv}")

    def _mark_client(self, v):
        if v not in self.id_origin:
            self.id_origin[v] = "client"

    def _mark_server(self, v):
        if v in self.id_origin:
            if self.id_origin[v] == "client":
                self.id_origin[v] = "both"
        else:
            self.id_origin[v] = "server"

    def _record(self, v, k, direction, msg_id, method, path):
        self.id_index[v][k][direction].add(msg_id)
        self.id_timeline[v].append((msg_id, method, path))

    def get_semantic_hits(self):
        hits = defaultdict(lambda: defaultdict(set))
        for v, timeline in self.id_timeline.items():
            for _, method, path in timeline:
                if not path or not method:
                    continue
                ep = f"{method} {extract_base_path(path)}"
                if ep in Config.BLACKLIST_ENDPOINTS:
                    continue
                for k in self.id_index[v]:
                    if k.lower() == "id":
                        if self.id_origin.get(v) == "server":
                            continue
                        if not is_likely_id_value(v):
                            continue
                    if k.lower() in Config.SEMANTIC_ID_KEYS:
                        hits[v][k].add(ep)
        return hits

    def get_relevant_msg_ids(self):
        relevant = set()
        hits = self.get_semantic_hits()
        for v, keys in hits.items():
            for k in keys:
                relevant.update(self.id_index[v][k].get("request", []))
                relevant.update(self.id_index[v][k].get("response", []))
        return sorted(relevant)

# ============================================================
# OUTPUT
# ============================================================

def print_graphql_summary(analyzer):
    print("\n" + "=" * 60)
    print("GRAPHQL ANALYSIS")
    print("=" * 60)

    for op, msgs in sorted(analyzer.graphql_operations.items()):
        print(f"{op}: {len(msgs)} calls")

    if analyzer.client_supplied_ids:
        print("\nClient-supplied ID candidates:")
        for v in sorted(analyzer.client_supplied_ids):
            print(f"  - {v}")

def print_idor_candidates(analyzer):
    print("\n" + "=" * 60)
    print("HIGH-SIGNAL IDOR CANDIDATES")
    print("=" * 60)

    hits = analyzer.get_semantic_hits()
    for v in sorted(hits):
        print(f"\n{v} [{analyzer.id_origin.get(v)}]")
        ops = analyzer.id_to_operations.get(v)
        if ops:
            print(f"  operations: {', '.join(sorted(ops))}")
        for k in hits[v]:
            print(f"  {k}")
            for ep in hits[v][k]:
                print(f"    {ep}")

def print_endpoint_grouped(analyzer):
    print("\n" + "=" * 60)
    print("IDOR CANDIDATES (BY ENDPOINT)")
    print("=" * 60)

    grouped = defaultdict(set)
    for v, keys in analyzer.get_semantic_hits().items():
        for k, eps in keys.items():
            for ep in eps:
                grouped[ep].add(v)

    for ep in sorted(grouped):
        print(f"\n{ep}")
        for v in sorted(grouped[ep]):
            print(f"  - {v}")

def print_cooccurrence(analyzer):
    print("\n" + "=" * 60)
    print("ID CO-OCCURRENCE")
    print("=" * 60)
    for k in analyzer.id_cooccurrence:
        print(f"{k} → {sorted(analyzer.id_cooccurrence[k])}")

def export_csv(analyzer, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "origin", "semantic_key", "endpoint"])
        for v, keys in analyzer.get_semantic_hits().items():
            for k, eps in keys.items():
                for ep in eps:
                    w.writerow([v, analyzer.id_origin.get(v), k, ep])

def export_relevant_transactions(analyzer, out_path):
    msg_ids = analyzer.get_relevant_msg_ids()
    if not msg_ids:
        return
    with open(out_path, "w", encoding="utf-8") as f:
        for msg_id in msg_ids:
            raw = analyzer.raw_messages.get(msg_id)
            if not raw:
                continue
            f.write("=" * 80 + "\n")
            f.write(f"MSG ID: {msg_id}\n")
            f.write(f"STATUS: {analyzer.status_by_msg.get(msg_id, 'unknown')}\n")
            f.write("=" * 80 + "\n\n")
            f.write("----- REQUEST -----\n")
            f.write(raw["request"])
            f.write("\n\n----- RESPONSE -----\n")
            f.write(raw["response"])
            f.write("\n\n")

# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: idor_analyzer.py <history.xml> [sitemap.xml]")
        sys.exit(1)

    history_xml = sys.argv[1]
    # sitemap_xml = sys.argv[2] if len(sys.argv) > 2 else None  # accepted, unused

    analyzer = IDORAnalyzer(history_xml)
    analyzer.analyze()

    if analyzer.graphql_operations:
        print_graphql_summary(analyzer)

    if view_mode in ("id", "both"):
        print_idor_candidates(analyzer)
    if view_mode in ("endpoint", "both"):
        print_endpoint_grouped(analyzer)
    if view_mode in ("cooccurrence", "both"):
        print_cooccurrence(analyzer)

    out_csv = f"{Path(history_xml).stem}_idor_candidates.csv"
    export_csv(analyzer, out_csv)

    tx_out = f"{Path(history_xml).stem}_idor_relevant_transactions.txt"
    export_relevant_transactions(analyzer, tx_out)

    print(f"\n[+] Exported to {out_csv}")
    print(f"[+] Exported to {tx_out}")

if __name__ == "__main__":
    main()
