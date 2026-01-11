#!/usr/bin/env python3
"""
IDOR START-LINE PERMUTATOR
=========================

Given:
- Burp XML
- Message ID
- IDORAnalyzer metadata

Produce:
- Exhaustive, deterministic start-line permutations
- Includes chained mutations as explicit state transitions
- No heuristics
- No filtering
- No scoring
- No request body/header replay (start-line only)

Chaining model:
- boundary(+1) → structural(double_slash_before) → ... (up to --chain-depth)
- Enumerated concretely and labeled algebraically
- Default chain depth = 2 (overrideable)

This script is downstream-only and read-only with respect to the analyzer.
"""

from __future__ import annotations

import sys
import re
import json
import argparse
from dataclasses import dataclass
from typing import List, Optional, Tuple

from urllib.parse import quote

from idor_analyzer import IDORAnalyzer, IDCandidate


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class StartLineMutation:
    method: str
    path: str
    mutation_class: str
    note: str = ""  # optional explanation / algebraic label


@dataclass(frozen=True)
class ChainStep:
    class_name: str   # boundary / structural / uuid_boundary
    label: str        # boundary(+1), structural(double_slash_before), ...
    path: str         # resulting path
    id_value: str     # current ID token in the path (may change with encoding/type-confusion)


# ============================================================
# CONSTANTS (DETERMINISTIC)
# ============================================================

MAX_INT32 = "2147483647"
MAX_INT64 = "9223372036854775807"
MIN_INT32 = "-2147483648"

BOUNDARY_OFFSETS = [1, -1]
BOUNDARY_ABSOLUTE = ["0", "-1", MAX_INT32, MAX_INT64, MIN_INT32]

STRUCTURAL_MUTATIONS = [
    "trailing_slash",
    "double_slash_before",
    "double_slash_after",
    "double_slash_wrap",
    "dot_segment_before",
    "dot_segment_after",
    "leading_zero_1",
    "leading_zero_2",
    "leading_zero_3",
    "hex_encoding",
    "octal_encoding",
    "type_confusion_alpha",
    "type_confusion_quote",
    "type_confusion_bracket",
    "null_byte",
    "double_null_byte",
    "space_suffix",
    "tab_suffix",
    "newline_suffix",
    "url_encode",
    "double_url_encode",
    "uppercase_path",
    "lowercase_path",
]

SUBPATH_SUFFIXES = ["details", "info", "data", "view", "get", "read"]
VERSION_PREFIXES = ["/v1", "/v2", "/v3", "/api/v1", "/api/v2"]

NULL_UUID = "00000000-0000-0000-0000-000000000000"
MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

PLACEHOLDER = "{DIFFERENT_VALID_ID}"


# ============================================================
# ID TYPE DETECTION
# ============================================================

def is_numeric_id(v: str) -> bool:
    return v.isdigit() and len(v) >= 3


def is_uuid(v: str) -> bool:
    return bool(re.match(
        r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
        v, re.I))


# ============================================================
# POLICY (NO HEURISTICS)
# ============================================================

def is_identity_key(key: str) -> bool:
    k = (key or "").lower()
    return any(x in k for x in (
        "user", "account", "org", "tenant", "workspace", "owner", "creator", "author"
    ))


def requires_placeholder_only(c: IDCandidate) -> bool:
    return (
        bool(getattr(c, "token_bound", False)) or
        getattr(c, "origin", None) == "server" or
        is_identity_key(getattr(c, "key", "")) or
        str(getattr(c, "id_value", "")).startswith(("gid://", "urn:", "uuid:", "oid:"))
    )


def _placeholder_reason(c: IDCandidate) -> str:
    if bool(getattr(c, "token_bound", False)):
        return "token-bound: mutations break signature"
    if getattr(c, "origin", None) == "server":
        return "server-only: cannot manipulate response-only ID"
    if is_identity_key(getattr(c, "key", "")):
        return f"identity key '{getattr(c,'key','')}' needs real cross-account ID"
    if str(getattr(c, "id_value", "")).startswith(("gid://", "urn:", "uuid:", "oid:")):
        return "opaque identifier: cannot enumerate"
    return "placeholder required"


# ============================================================
# PATH HELPERS
# ============================================================

def _split_query(path: str) -> Tuple[str, str]:
    if "?" in path:
        base, q = path.split("?", 1)
        return base, "?" + q
    return path, ""


def replace_id(path: str, old: str, new: str) -> str:
    if f"/{old}/" in path:
        return path.replace(f"/{old}/", f"/{new}/", 1)
    if f"/{old}?" in path:
        return path.replace(f"/{old}?", f"/{new}?", 1)
    if path.endswith(f"/{old}"):
        return path[:-len(old)] + new
    return path.replace(old, new, 1)


def apply_structural_mutation(path: str, idv: str, kind: str) -> Optional[Tuple[str, str]]:
    """
    Returns (mutated_path, mutated_idv) or None.
    mutated_idv matters for chaining (because some structural mutations change the ID token).
    """
    base, query = _split_query(path)

    # ===== topology-only (id token unchanged) =====
    if kind == "trailing_slash":
        if base.endswith("/"):
            return None
        return (base + "/" + query, idv)

    if kind == "double_slash_before":
        needle = f"/{idv}"
        if needle not in base:
            return None
        return (base.replace(needle, f"//{idv}", 1) + query, idv)

    if kind == "double_slash_after":
        needle = f"/{idv}/"
        if needle not in base:
            return None
        return (base.replace(needle, f"/{idv}//", 1) + query, idv)

    if kind == "double_slash_wrap":
        needle = f"/{idv}/"
        if needle not in base:
            return None
        return (base.replace(needle, f"//{idv}//", 1) + query, idv)

    if kind == "dot_segment_before":
        needle = f"/{idv}"
        if needle not in base:
            return None
        return (base.replace(needle, f"/./{idv}", 1) + query, idv)

    if kind == "dot_segment_after":
        needle = f"/{idv}/"
        if needle in base:
            return (base.replace(needle, f"/{idv}/./", 1) + query, idv)
        if base.endswith(f"/{idv}"):
            return (base + "/." + query, idv)
        return None

    # ===== id-token mutations (id token changes) =====
    if kind == "leading_zero_1" and is_numeric_id(idv):
        new_id = "0" + idv
        return (replace_id(path, idv, new_id), new_id)

    if kind == "leading_zero_2" and is_numeric_id(idv):
        new_id = "00" + idv
        return (replace_id(path, idv, new_id), new_id)

    if kind == "leading_zero_3" and is_numeric_id(idv):
        new_id = "000" + idv
        return (replace_id(path, idv, new_id), new_id)

    if kind == "hex_encoding" and is_numeric_id(idv):
        try:
            new_id = hex(int(idv))
        except ValueError:
            return None
        return (replace_id(path, idv, new_id), new_id)

    if kind == "octal_encoding" and is_numeric_id(idv):
        try:
            new_id = oct(int(idv))
        except ValueError:
            return None
        return (replace_id(path, idv, new_id), new_id)

    if kind == "type_confusion_alpha":
        new_id = idv + "abc"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "type_confusion_quote":
        new_id = idv + "'"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "type_confusion_bracket":
        new_id = idv + "[]"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "null_byte":
        new_id = idv + "%00"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "double_null_byte":
        new_id = idv + "%2500"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "space_suffix":
        new_id = idv + "%20"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "tab_suffix":
        new_id = idv + "%09"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "newline_suffix":
        new_id = idv + "%0a"
        return (replace_id(path, idv, new_id), new_id)

    if kind == "url_encode":
        new_id = quote(idv, safe="")
        if new_id == idv:
            return None
        return (replace_id(path, idv, new_id), new_id)

    if kind == "double_url_encode":
        new_id = quote(quote(idv, safe=""), safe="")
        return (replace_id(path, idv, new_id), new_id)

    if kind == "uppercase_path":
        up = path.upper()
        if up == path:
            return None
        return (up, idv.upper())

    if kind == "lowercase_path":
        lo = path.lower()
        if lo == path:
            return None
        return (lo, idv.lower())

    return None


# ============================================================
# PRIMITIVE STEP GENERATORS (FIRST-ORDER EDGES)
# ============================================================

def boundary_steps(path: str, idv: str) -> List[ChainStep]:
    out: List[ChainStep] = []
    if is_numeric_id(idv):
        base = int(idv)

        for off in BOUNDARY_OFFSETS:
            new_id = str(base + off)
            out.append(ChainStep(
                "boundary",
                f"boundary({off:+d})",
                replace_id(path, idv, new_id),
                new_id,
            ))

        for b in BOUNDARY_ABSOLUTE:
            out.append(ChainStep(
                "boundary",
                f"boundary({b})",
                replace_id(path, idv, b),
                b,
            ))
    return out


def uuid_steps(path: str, idv: str) -> List[ChainStep]:
    out: List[ChainStep] = []
    if is_uuid(idv):
        out.append(ChainStep("uuid_boundary", "uuid(null)", replace_id(path, idv, NULL_UUID), NULL_UUID))
        out.append(ChainStep("uuid_boundary", "uuid(max)", replace_id(path, idv, MAX_UUID), MAX_UUID))
        parts = idv.split("-")
        if len(parts) == 5 and len(parts[2]) == 4:
            modified = f"{parts[0]}-{parts[1]}-0{parts[2][1:]}-{parts[3]}-{parts[4]}"
            out.append(ChainStep("uuid_boundary", "uuid(version=0)", replace_id(path, idv, modified), modified))
    return out


def structural_steps(path: str, idv: str) -> List[ChainStep]:
    out: List[ChainStep] = []
    for k in STRUCTURAL_MUTATIONS:
        res = apply_structural_mutation(path, idv, k)
        if not res:
            continue
        new_path, new_idv = res
        if new_path == path:
            continue
        out.append(ChainStep("structural", f"structural({k})", new_path, new_idv))
    return out


def subpath_mutations(method: str, path: str) -> List[StartLineMutation]:
    base, query = _split_query(path)
    base = base.rstrip("/")
    out: List[StartLineMutation] = []
    for suffix in SUBPATH_SUFFIXES:
        out.append(StartLineMutation(method, f"{base}/{suffix}{query}", "subpath", note=f"append /{suffix}"))
    return out


def version_prefix_mutations(method: str, path: str) -> List[StartLineMutation]:
    out: List[StartLineMutation] = []
    for prefix in VERSION_PREFIXES:
        if not path.startswith(prefix):
            out.append(StartLineMutation(method, prefix + path, "version_prefix", note=f"inject {prefix}"))

    m = re.match(r"^(/(?:api/)?v)(\d+)(/.*)$", path)
    if m:
        pre, num, rest = m.groups()
        try:
            n = int(num)
        except ValueError:
            n = 0
        for v in range(n - 1, 0, -1):
            out.append(StartLineMutation(method, f"{pre}{v}{rest}", "version_downgrade", note=f"v{num} → v{v}"))
    return out


# ============================================================
# FLAT MUTATION ENGINE (NO CHAINING)
# ============================================================

def generate_flat_mutations(method: str, path: str, c: IDCandidate) -> List[StartLineMutation]:
    idv = str(getattr(c, "id_value", ""))

    if requires_placeholder_only(c):
        return [StartLineMutation(method, replace_id(path, idv, PLACEHOLDER), "placeholder", note=_placeholder_reason(c))]

    out: List[StartLineMutation] = []

    for s in boundary_steps(path, idv):
        out.append(StartLineMutation(method, s.path, "boundary", note=s.label))

    for s in uuid_steps(path, idv):
        out.append(StartLineMutation(method, s.path, "uuid_boundary", note=s.label))

    for s in structural_steps(path, idv):
        out.append(StartLineMutation(method, s.path, "structural", note=s.label))

    out.extend(subpath_mutations(method, path))
    out.extend(version_prefix_mutations(method, path))

    out.append(StartLineMutation(method, replace_id(path, idv, PLACEHOLDER), "placeholder", note="manual cross-user test"))
    return out


# ============================================================
# CHAIN ENGINE (STATE GRAPH, DEPTH>=2)
# ============================================================

def generate_chain_mutations(method: str, path: str, c: IDCandidate, depth: int) -> List[StartLineMutation]:
    """
    Deterministic chaining policy:
      step 1: boundary(...)  (requires numeric ID)
      steps 2..depth: structural(...)
    """
    if depth < 2 or requires_placeholder_only(c):
        return []

    start_id = str(getattr(c, "id_value", ""))
    if not is_numeric_id(start_id):
        return []

    # Step 1 (boundary)
    frontier: List[Tuple[str, str, List[str]]] = []
    for b in boundary_steps(path, start_id):
        frontier.append((b.path, b.id_value, [b.label]))

    results: List[StartLineMutation] = []
    seen_paths: set[Tuple[str, str]] = set()

    # Steps 2..depth (structural)
    for _ in range(2, depth + 1):
        new_frontier: List[Tuple[str, str, List[str]]] = []
        for cur_path, cur_idv, labels in frontier:
            for s in structural_steps(cur_path, cur_idv):
                new_labels = labels + [s.label]
                note = " → ".join(new_labels)
                mclass = "chain:" + "+".join(new_labels)

                key = (method, s.path)
                if key not in seen_paths:
                    seen_paths.add(key)
                    results.append(StartLineMutation(method, s.path, mclass, note=note))

                new_frontier.append((s.path, s.id_value, new_labels))
        frontier = new_frontier
        if not frontier:
            break

    return results


# ============================================================
# OUTPUT (TEXT / BURP / JSON)
# ============================================================

def format_text_report(
    msg_id: int,
    host: str,
    method: str,
    path: str,
    candidate: IDCandidate,
    flat: List[StartLineMutation],
    chained: List[StartLineMutation],
    verbose: bool,
) -> str:
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("START-LINE PERMUTATIONS")
    lines.append("=" * 60)
    lines.append(f"Message ID: {msg_id}")
    lines.append(f"Host: {host}")
    lines.append(f"Original: {method} {path}")
    lines.append("")

    lines.append("=" * 60)
    lines.append("REQUEST CONTEXT")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Original request:")
    lines.append(f"  {method} {path}")
    lines.append("")
    lines.append(f"ID key:    {getattr(candidate, 'key', '')}")
    lines.append(f"ID value:  {getattr(candidate, 'id_value', '')}")
    lines.append(f"Origin:    {getattr(candidate, 'origin', '')}")
    srcs = getattr(candidate, "sources", [])
    if isinstance(srcs, (set, list, tuple)):
        lines.append(f"Sources:   {', '.join(sorted(map(str, srcs)))}")
    else:
        lines.append(f"Sources:   {srcs}")
    if bool(getattr(candidate, "token_bound", False)):
        lines.append(f"Token:     BOUND ({getattr(candidate, 'token_strength', '')})")
    lines.append("")

    def section(title: str, muts: List[StartLineMutation]) -> None:
        lines.append("=" * 60)
        lines.append(title)
        lines.append("=" * 60)
        if not muts:
            lines.append("(none)\n")
            return
        for i, m in enumerate(muts, 1):
            lines.append(f"\n[{i}] {m.mutation_class}")
            lines.append(f"    {m.method} {m.path}")
            if verbose and m.note:
                lines.append(f"    Note: {m.note}")
        lines.append("")

    section("FLAT (FIRST-ORDER) MUTATIONS", flat)
    section("CHAINED MUTATIONS", chained)

    lines.append("=" * 60)
    lines.append("PLAIN START-LINES (COPY-PASTE)")
    lines.append("=" * 60)
    lines.append("")
    for m in flat + chained:
        lines.append(f"{m.method} {m.path}")
    lines.append("")
    return "\n".join(lines)


def _score(c: IDCandidate) -> float:
    try:
        return float(getattr(c, "score", 0.0))
    except Exception:
        return 0.0


def _pick_candidates(analyzer: IDORAnalyzer, msg_id: int, path: str, all_candidates: bool) -> List[IDCandidate]:
    candidates = analyzer.get_candidates_for_msg(msg_id) or []
    if not candidates:
        return []

    in_path = [c for c in candidates if str(getattr(c, "id_value", "")) in path]
    not_in_path = [c for c in candidates if str(getattr(c, "id_value", "")) not in path]

    in_path.sort(key=_score, reverse=True)
    not_in_path.sort(key=_score, reverse=True)

    ordered = in_path + not_in_path
    return ordered if all_candidates else ordered[:1]


def main() -> None:
    ap = argparse.ArgumentParser(description="IDOR Start-Line Permutator (flat + chained)")
    ap.add_argument("xml", help="Burp history XML")
    ap.add_argument("msg_id", type=int, help="Message ID")
    ap.add_argument("--chain-depth", type=int, default=2, help="Chain depth (default: 2)")
    ap.add_argument("--all-candidates", action="store_true", help="Process all candidates (default: only top)")
    ap.add_argument("--format", choices=["text", "burp", "json"], default="text", help="Output format")
    ap.add_argument("-v", "--verbose", action="store_true", help="Include notes / algebraic labels (text)")
    args = ap.parse_args()

    analyzer = IDORAnalyzer(args.xml)
    analyzer.analyze()

    raw_req = analyzer.raw_messages[args.msg_id]["request"]
    first_line = raw_req.splitlines()[0]
    parts = first_line.split()
    if len(parts) < 2:
        print("Could not parse request line.", file=sys.stderr)
        sys.exit(1)

    method, path = parts[0], parts[1]
    host = getattr(analyzer, "host_by_msg", {}).get(args.msg_id, "unknown")

    selected = _pick_candidates(analyzer, args.msg_id, path, args.all_candidates)
    if not selected:
        print("No IDOR candidates associated with this message.")
        return

    flat_all: List[StartLineMutation] = []
    chain_all: List[StartLineMutation] = []
    seen: set[Tuple[str, str]] = set()
    processed: List[IDCandidate] = []

    for c in selected:
        idv = str(getattr(c, "id_value", ""))
        if idv not in path:
            continue

        processed.append(c)

        flat = generate_flat_mutations(method, path, c)
        chained = generate_chain_mutations(method, path, c, args.chain_depth)

        for m in flat:
            k = (m.method, m.path)
            if k not in seen:
                seen.add(k)
                flat_all.append(m)

        for m in chained:
            k = (m.method, m.path)
            if k not in seen:
                seen.add(k)
                chain_all.append(m)

    if not processed:
        print("No candidates with IDs in path.")
        return

    if args.format == "burp":
        for m in flat_all + chain_all:
            print(f"{m.method} {m.path} HTTP/1.1")
        return

    if args.format == "json":
        data = {
            "msg_id": args.msg_id,
            "host": host,
            "original": f"{method} {path}",
            "chain_depth": args.chain_depth,
            "candidates": [
                {
                    "key": getattr(c, "key", ""),
                    "value": getattr(c, "id_value", ""),
                    "origin": getattr(c, "origin", ""),
                    "sources": sorted(map(str, getattr(c, "sources", []))) if isinstance(getattr(c, "sources", []), (set, list, tuple)) else [],
                    "token_bound": bool(getattr(c, "token_bound", False)),
                }
                for c in processed
            ],
            "flat_mutations": [
                {"method": m.method, "path": m.path, "class": m.mutation_class, "note": m.note}
                for m in flat_all
            ],
            "chained_mutations": [
                {"method": m.method, "path": m.path, "class": m.mutation_class, "note": m.note}
                for m in chain_all
            ],
        }
        print(json.dumps(data, indent=2))
        return

    print(format_text_report(args.msg_id, host, method, path, processed[0], flat_all, chain_all, args.verbose))


if __name__ == "__main__":
    main()
