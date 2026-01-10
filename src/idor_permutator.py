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
- No heuristics
- No filtering
- No scoring
- No request body/header replay (start-line only)

This script is downstream-only and read-only with respect to the analyzer.

Changes from original:
- Added origin=="server" check (cannot mutate response-only IDs)
- Added UUID detection and UUID-specific mutations
- Added more structural mutations (double encoding, more whitespace, case)
- Added negative numeric values
- Improved replace_id to handle edge cases
- Added octal encoding for numeric IDs
"""

import sys
import re
import argparse
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote

# Import analyzer (unchanged)
from idor_analyzer import IDORAnalyzer, IDCandidate


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class StartLineMutation:
    method: str
    path: str
    mutation_class: str
    note: str = ""  # Optional explanation


# ============================================================
# CONSTANTS (DETERMINISTIC)
# ============================================================

MAX_INT32 = "2147483647"
MAX_INT64 = "9223372036854775807"
MIN_INT32 = "-2147483648"

# Boundary values for numeric IDs
BOUNDARY_OFFSETS = [1, -1]
BOUNDARY_ABSOLUTE = [
    "0",
    "-1",
    MAX_INT32,
    MAX_INT64,
    MIN_INT32,
]

# Structural path mutations
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

# Subpath suffixes to try
SUBPATH_SUFFIXES = [
    "details",
    "info", 
    "data",
    "view",
    "get",
    "read",
]

# Version prefixes to inject
VERSION_PREFIXES = [
    "/v1",
    "/v2",
    "/v3",
    "/api/v1",
    "/api/v2",
]

# UUID-specific mutations
NULL_UUID = "00000000-0000-0000-0000-000000000000"
MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

PLACEHOLDER = "{DIFFERENT_VALID_ID}"


# ============================================================
# ID TYPE DETECTION
# ============================================================

def is_numeric_id(value: str) -> bool:
    """Check if value is a numeric ID (3+ digits)."""
    return value.isdigit() and len(value) >= 3


def is_uuid(value: str) -> bool:
    """Check if value is a UUID (any version)."""
    uuid_pattern = re.compile(
        r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(value))


def is_hex_id(value: str) -> bool:
    """Check if value is a hex string (not UUID)."""
    if is_uuid(value):
        return False
    return bool(re.match(r'^[a-f0-9]{8,}$', value, re.IGNORECASE))


def is_base64_id(value: str) -> bool:
    """Check if value looks like base64/opaque ID."""
    if is_uuid(value) or is_hex_id(value) or is_numeric_id(value):
        return False
    return bool(re.match(r'^[A-Za-z0-9_-]{16,}$', value))


# ============================================================
# POLICY DECISION (NO HEURISTICS)
# ============================================================

def is_identity_key(key: str) -> bool:
    """Check if key represents identity/tenancy."""
    k = (key or "").lower()
    return any(
        x in k
        for x in ("user", "account", "org", "tenant", "workspace", "owner", "creator", "author")
    )


def requires_placeholder_only(candidate: IDCandidate) -> bool:
    """
    Deterministic policy:
    If ANY of these are true → placeholder-only (no auto-mutation).
    
    Returns True when mutations would be:
    - Semantically invalid (token-bound)
    - Require cross-account setup (identity keys)
    - Impossible to enumerate (opaque formats)
    - Semantically impossible (response-only IDs)
    """
    # 1. Token-bound: mutations break signature
    if candidate.token_bound:
        return True

    # 2. Identity keys: need real cross-account ID
    if candidate.origin in {"client", "both"} and is_identity_key(candidate.key):
        return True

    # 3. Opaque identifiers: cannot numerically mutate
    if candidate.id_value.startswith(("gid://", "urn:", "uuid:", "oid:")):
        return True

    # 4. Server-only origin: ID only appears in responses
    #    Cannot manipulate what you never send
    if candidate.origin == "server":
        return True

    return False


# ============================================================
# PATH MUTATION HELPERS
# ============================================================

def find_id_in_path(path: str, id_value: str) -> Optional[tuple]:
    """
    Find ID value position in path.
    Returns (start, end) indices or None.
    """
    # Look for /id_value/ or /id_value at end
    patterns = [
        f"/{id_value}/",
        f"/{id_value}?",
        f"/{id_value}$",
    ]
    
    for pattern in patterns:
        if pattern.endswith("$"):
            # End of path
            if path.endswith(f"/{id_value}"):
                start = path.rfind(f"/{id_value}") + 1
                return (start, start + len(id_value))
        else:
            idx = path.find(pattern[:len(pattern)-1])
            if idx >= 0:
                return (idx + 1, idx + 1 + len(id_value))
    
    # Fallback: simple find
    idx = path.find(id_value)
    if idx >= 0:
        return (idx, idx + len(id_value))
    
    return None


def replace_id(path: str, old: str, new: str) -> str:
    """
    Replace ID value in path, handling edge cases.
    Preserves path structure.
    """
    # Try structured replacement first
    if f"/{old}/" in path:
        return path.replace(f"/{old}/", f"/{new}/", 1)
    if f"/{old}?" in path:
        return path.replace(f"/{old}?", f"/{new}?", 1)
    if path.endswith(f"/{old}"):
        return path[:-len(old)] + new
    
    # Fallback: direct replacement
    return path.replace(old, new, 1)


def apply_structural_mutation(path: str, id_value: str, kind: str) -> Optional[str]:
    """
    Apply a structural mutation to the path.
    Returns None if mutation not applicable.
    """
    pos = find_id_in_path(path, id_value)
    if not pos:
        return None
    
    start, end = pos
    before_id = path[:start]
    after_id = path[end:]
    
    # === SLASH MUTATIONS ===
    
    if kind == "trailing_slash":
        if not path.rstrip("?").split("?")[0].endswith("/"):
            base = path.split("?")[0]
            query = "?" + path.split("?")[1] if "?" in path else ""
            return base + "/" + query
        return None
    
    if kind == "double_slash_before":
        # /boards/123 -> /boards//123
        if not before_id.endswith("//"):
            return before_id.rstrip("/") + "//" + id_value + after_id
        return None
    
    if kind == "double_slash_after":
        # /boards/123/items -> /boards/123//items
        if after_id and not after_id.startswith("//"):
            return before_id + id_value + "/" + after_id
        return None
    
    if kind == "double_slash_wrap":
        return before_id.rstrip("/") + "//" + id_value + "//" + after_id.lstrip("/")
    
    # === DOT SEGMENT MUTATIONS ===
    
    if kind == "dot_segment_before":
        return before_id + "./" + id_value + after_id
    
    if kind == "dot_segment_after":
        if after_id:
            return before_id + id_value + "/./" + after_id.lstrip("/")
        return before_id + id_value + "/."
    
    # === NUMERIC ENCODING (only for numeric IDs) ===
    
    if kind == "leading_zero_1" and is_numeric_id(id_value):
        return replace_id(path, id_value, "0" + id_value)
    
    if kind == "leading_zero_2" and is_numeric_id(id_value):
        return replace_id(path, id_value, "00" + id_value)
    
    if kind == "leading_zero_3" and is_numeric_id(id_value):
        return replace_id(path, id_value, "000" + id_value)
    
    if kind == "hex_encoding" and is_numeric_id(id_value):
        try:
            hex_val = hex(int(id_value))
            return replace_id(path, id_value, hex_val)
        except ValueError:
            return None
    
    if kind == "octal_encoding" and is_numeric_id(id_value):
        try:
            oct_val = oct(int(id_value))
            return replace_id(path, id_value, oct_val)
        except ValueError:
            return None
    
    # === TYPE CONFUSION ===
    
    if kind == "type_confusion_alpha":
        return replace_id(path, id_value, id_value + "abc")
    
    if kind == "type_confusion_quote":
        return replace_id(path, id_value, id_value + "'")
    
    if kind == "type_confusion_bracket":
        return replace_id(path, id_value, id_value + "[]")
    
    # === NULL/WHITESPACE ===
    
    if kind == "null_byte":
        return replace_id(path, id_value, id_value + "%00")
    
    if kind == "double_null_byte":
        return replace_id(path, id_value, id_value + "%2500")
    
    if kind == "space_suffix":
        return replace_id(path, id_value, id_value + "%20")
    
    if kind == "tab_suffix":
        return replace_id(path, id_value, id_value + "%09")
    
    if kind == "newline_suffix":
        return replace_id(path, id_value, id_value + "%0a")
    
    # === URL ENCODING ===
    
    if kind == "url_encode":
        encoded = quote(id_value, safe="")
        if encoded != id_value:
            return replace_id(path, id_value, encoded)
        return None
    
    if kind == "double_url_encode":
        double_encoded = quote(quote(id_value, safe=""), safe="")
        return replace_id(path, id_value, double_encoded)
    
    # === CASE MUTATIONS ===
    
    if kind == "uppercase_path":
        upper = path.upper()
        if upper != path:
            return upper
        return None
    
    if kind == "lowercase_path":
        lower = path.lower()
        if lower != path:
            return lower
        return None
    
    return None


# ============================================================
# MUTATION ENGINE
# ============================================================

def generate_mutations(
    method: str,
    path: str,
    candidate: IDCandidate
) -> List[StartLineMutation]:
    """
    Generate all applicable start-line mutations for a candidate.
    
    Mutation order:
    1. PLACEHOLDER_ONLY candidates -> single placeholder
    2. Boundary mutations (numeric)
    3. UUID mutations (if UUID)
    4. Structural path mutations
    5. Subpath variants
    6. Version prefix injections
    7. Placeholder (always last for FULL_MUTATION)
    """
    out: List[StartLineMutation] = []
    id_value = candidate.id_value

    # === PLACEHOLDER ONLY ===
    if requires_placeholder_only(candidate):
        reason = _get_placeholder_reason(candidate)
        out.append(
            StartLineMutation(
                method,
                replace_id(path, id_value, PLACEHOLDER),
                "placeholder",
                note=reason
            )
        )
        return out

    # === NUMERIC BOUNDARY MUTATIONS ===
    if is_numeric_id(id_value):
        base = int(id_value)
        
        # Adjacent values (±1)
        for offset in BOUNDARY_OFFSETS:
            new_val = str(base + offset)
            out.append(
                StartLineMutation(
                    method,
                    replace_id(path, id_value, new_val),
                    "boundary",
                    note=f"adjacent: {id_value} → {new_val}"
                )
            )
        
        # Absolute boundary values
        for boundary in BOUNDARY_ABSOLUTE:
            out.append(
                StartLineMutation(
                    method,
                    replace_id(path, id_value, boundary),
                    "boundary",
                    note=f"absolute: {boundary}"
                )
            )

    # === UUID MUTATIONS ===
    if is_uuid(id_value):
        # Null UUID
        out.append(
            StartLineMutation(
                method,
                replace_id(path, id_value, NULL_UUID),
                "uuid_boundary",
                note="null UUID"
            )
        )
        # Max UUID
        out.append(
            StartLineMutation(
                method,
                replace_id(path, id_value, MAX_UUID),
                "uuid_boundary",
                note="max UUID"
            )
        )
        # Version manipulation (change version nibble)
        parts = id_value.split("-")
        if len(parts) == 5:
            # Change version to 0
            modified = f"{parts[0]}-{parts[1]}-0{parts[2][1:]}-{parts[3]}-{parts[4]}"
            out.append(
                StartLineMutation(
                    method,
                    replace_id(path, id_value, modified),
                    "uuid_boundary",
                    note="version nibble zeroed"
                )
            )

    # === STRUCTURAL PATH MUTATIONS ===
    for kind in STRUCTURAL_MUTATIONS:
        mutated = apply_structural_mutation(path, id_value, kind)
        if mutated and mutated != path:
            out.append(
                StartLineMutation(
                    method,
                    mutated,
                    f"structural:{kind}"
                )
            )

    # === SUBPATH VARIANTS ===
    base_path = path.split("?")[0].rstrip("/")
    query = "?" + path.split("?")[1] if "?" in path else ""
    
    for suffix in SUBPATH_SUFFIXES:
        out.append(
            StartLineMutation(
                method,
                f"{base_path}/{suffix}{query}",
                "subpath",
                note=f"append /{suffix}"
            )
        )

    # === VERSION PREFIX INJECTION ===
    for prefix in VERSION_PREFIXES:
        # Don't add if already has this prefix
        if not path.startswith(prefix):
            out.append(
                StartLineMutation(
                    method,
                    prefix + path,
                    "version_prefix",
                    note=f"inject {prefix}"
                )
            )
    
    # Check for existing version and try downgrade
    version_match = re.match(r'^(/(?:api/)?v)(\d+)(/.*)$', path)
    if version_match:
        prefix, ver_num, rest = version_match.groups()
        ver_int = int(ver_num)
        if ver_int > 1:
            for v in range(ver_int - 1, 0, -1):
                out.append(
                    StartLineMutation(
                        method,
                        f"{prefix}{v}{rest}",
                        "version_downgrade",
                        note=f"v{ver_num} → v{v}"
                    )
                )

    # === PLACEHOLDER (ALWAYS LAST) ===
    out.append(
        StartLineMutation(
            method,
            replace_id(path, id_value, PLACEHOLDER),
            "placeholder",
            note="manual cross-user test"
        )
    )

    return out


def _get_placeholder_reason(candidate: IDCandidate) -> str:
    """Get human-readable reason for placeholder-only."""
    if candidate.token_bound:
        return "token-bound: mutations break signature"
    if candidate.origin == "server":
        return "server-only: cannot manipulate response-only ID"
    if is_identity_key(candidate.key):
        return f"identity key '{candidate.key}': needs real cross-account ID"
    if candidate.id_value.startswith(("gid://", "urn:")):
        return "opaque identifier: cannot enumerate"
    return "placeholder required"


# ============================================================
# CLI
# ============================================================

def format_output(mutations: List[StartLineMutation], verbose: bool = False) -> str:
    """Format mutations for display."""
    lines = []
    current_class = None
    
    for i, m in enumerate(mutations, 1):
        # Group header
        base_class = m.mutation_class.split(":")[0]
        if base_class != current_class:
            current_class = base_class
            lines.append(f"\n=== {current_class.upper()} ===")
        
        lines.append(f"\n[{i}] {m.mutation_class}")
        lines.append(f"    {m.method} {m.path}")
        if verbose and m.note:
            lines.append(f"    Note: {m.note}")
    
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="IDOR Start-Line Permutator")
    ap.add_argument("xml", help="Burp history XML")
    ap.add_argument("msg_id", type=int, help="Message ID")
    ap.add_argument("-v", "--verbose", action="store_true", help="Show mutation notes")
    ap.add_argument("--all-candidates", action="store_true", 
                    help="Generate mutations for all candidates (not just top)")
    ap.add_argument("--format", choices=["text", "burp", "json"], default="text",
                    help="Output format")
    args = ap.parse_args()

    analyzer = IDORAnalyzer(args.xml)
    analyzer.analyze()

    candidates = analyzer.get_candidates_for_msg(args.msg_id)

    if not candidates:
        print("No IDOR candidates associated with this message.")
        sys.exit(0)

    # Get request details
    raw_req = analyzer.raw_messages[args.msg_id]["request"]
    first_line = raw_req.splitlines()[0]
    parts = first_line.split()
    if len(parts) < 2:
        print("Could not parse request line.")
        sys.exit(1)
    
    method, path = parts[0], parts[1]
    host = analyzer.host_by_msg.get(args.msg_id, "unknown")

    # Select candidates
    if args.all_candidates:
        selected = sorted(candidates, key=lambda c: c.score, reverse=True)
    else:
        selected = [sorted(candidates, key=lambda c: c.score, reverse=True)[0]]

    all_mutations: List[StartLineMutation] = []
    seen: set = set()

    for candidate in selected:
        mutations = generate_mutations(method, path, candidate)
        for m in mutations:
            key = (m.method, m.path)
            if key not in seen:
                seen.add(key)
                all_mutations.append(m)

    # Output
    if args.format == "burp":
        for m in all_mutations:
            print(f"{m.method} {m.path} HTTP/1.1")
    
    elif args.format == "json":
        import json
        data = {
            "msg_id": args.msg_id,
            "host": host,
            "original": f"{method} {path}",
            "candidates": len(selected),
            "mutations": [
                {
                    "method": m.method,
                    "path": m.path,
                    "class": m.mutation_class,
                    "note": m.note,
                }
                for m in all_mutations
            ]
        }
        print(json.dumps(data, indent=2))
    
    else:  # text
        print(f"\n{'='*60}")
        print(f"START-LINE PERMUTATIONS")
        print(f"{'='*60}")
        print(f"Message ID: {args.msg_id}")
        print(f"Host: {host}")
        print(f"Original: {method} {path}")
        print(f"Candidates: {len(selected)}")
        print(f"Total mutations: {len(all_mutations)}")
        print(format_output(all_mutations, args.verbose))
        print()


if __name__ == "__main__":
    main()
