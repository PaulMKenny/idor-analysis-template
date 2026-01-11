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
    note: str = ""


@dataclass
class ChainSequence:
    """
    Executable chained sequence.
    steps[0] must be sent first, steps[1] second, etc.
    """
    label: str
    steps: List[StartLineMutation]


@dataclass(frozen=True)
class ChainStep:
    class_name: str
    label: str
    path: str
    id_value: str


# ============================================================
# CONSTANTS
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
# POLICY
# ============================================================

def is_identity_key(key: str) -> bool:
    k = (key or "").lower()
    return any(x in k for x in (
        "user", "account", "org", "tenant", "workspace",
        "owner", "creator", "author"
    ))


def requires_placeholder_only(c: IDCandidate) -> bool:
    return (
        bool(getattr(c, "token_bound", False)) or
        getattr(c, "origin", None) == "server" or
        is_identity_key(getattr(c, "key", "")) or
        str(getattr(c, "id_value", "")).startswith(("gid://", "urn:", "uuid:", "oid:"))
    )


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
    base, query = _split_query(path)

    if kind == "trailing_slash":
        if base.endswith("/"):
            return None
        return (base + "/" + query, idv)

    if kind == "double_slash_before":
        return (base.replace(f"/{idv}", f"//{idv}", 1) + query, idv) if f"/{idv}" in base else None

    if kind == "double_slash_after":
        return (base.replace(f"/{idv}/", f"/{idv}//", 1) + query, idv) if f"/{idv}/" in base else None

    if kind == "double_slash_wrap":
        return (base.replace(f"/{idv}/", f"//{idv}//", 1) + query, idv) if f"/{idv}/" in base else None

    if kind == "dot_segment_before":
        return (base.replace(f"/{idv}", f"/./{idv}", 1) + query, idv) if f"/{idv}" in base else None

    if kind == "dot_segment_after":
        if f"/{idv}/" in base:
            return (base.replace(f"/{idv}/", f"/{idv}/./", 1) + query, idv)
        if base.endswith(f"/{idv}"):
            return (base + "/." + query, idv)
        return None

    # ID-token changing structural mutations
    def mutate(new_id: str) -> Tuple[str, str]:
        return replace_id(path, idv, new_id), new_id

    if kind.startswith("leading_zero") and is_numeric_id(idv):
        return mutate("0" * int(kind[-1]) + idv)

    if kind == "hex_encoding" and is_numeric_id(idv):
        return mutate(hex(int(idv)))

    if kind == "octal_encoding" and is_numeric_id(idv):
        return mutate(oct(int(idv)))

    if kind == "type_confusion_alpha":
        return mutate(idv + "abc")

    if kind == "type_confusion_quote":
        return mutate(idv + "'")

    if kind == "type_confusion_bracket":
        return mutate(idv + "[]")

    if kind == "null_byte":
        return mutate(idv + "%00")

    if kind == "double_null_byte":
        return mutate(idv + "%2500")

    if kind == "space_suffix":
        return mutate(idv + "%20")

    if kind == "tab_suffix":
        return mutate(idv + "%09")

    if kind == "newline_suffix":
        return mutate(idv + "%0a")

    if kind == "url_encode":
        return mutate(quote(idv, safe=""))

    if kind == "double_url_encode":
        return mutate(quote(quote(idv, safe=""), safe=""))

    if kind == "uppercase_path":
        return (path.upper(), idv.upper()) if path.upper() != path else None

    if kind == "lowercase_path":
        return (path.lower(), idv.lower()) if path.lower() != path else None

    return None


# ============================================================
# PRIMITIVE STEP GENERATORS
# ============================================================

def boundary_steps(path: str, idv: str) -> List[ChainStep]:
    out: List[ChainStep] = []
    if is_numeric_id(idv):
        base = int(idv)
        for off in BOUNDARY_OFFSETS:
            nid = str(base + off)
            out.append(ChainStep("boundary", f"boundary({off:+d})", replace_id(path, idv, nid), nid))
        for b in BOUNDARY_ABSOLUTE:
            out.append(ChainStep("boundary", f"boundary({b})", replace_id(path, idv, b), b))
    return out


def structural_steps(path: str, idv: str) -> List[ChainStep]:
    out: List[ChainStep] = []
    for k in STRUCTURAL_MUTATIONS:
        res = apply_structural_mutation(path, idv, k)
        if not res:
            continue
        p, nid = res
        out.append(ChainStep("structural", f"structural({k})", p, nid))
    return out


# ============================================================
# FLAT MUTATION ENGINE (UNCHANGED)
# ============================================================

def generate_flat_mutations(method: str, path: str, c: IDCandidate) -> List[StartLineMutation]:
    idv = str(getattr(c, "id_value", ""))

    if requires_placeholder_only(c):
        return [StartLineMutation(method, replace_id(path, idv, PLACEHOLDER), "placeholder")]

    out: List[StartLineMutation] = []
    for s in boundary_steps(path, idv):
        out.append(StartLineMutation(method, s.path, "boundary", s.label))
    for s in structural_steps(path, idv):
        out.append(StartLineMutation(method, s.path, "structural", s.label))
    out.append(StartLineMutation(method, replace_id(path, idv, PLACEHOLDER), "placeholder"))
    return out


# ============================================================
# CHAIN ENGINE (FULL SEQUENCES)
# ============================================================

def generate_chain_sequences(method: str, path: str, c: IDCandidate, depth: int) -> List[ChainSequence]:
    if depth < 2 or requires_placeholder_only(c):
        return []

    start_id = str(getattr(c, "id_value", ""))
    if not is_numeric_id(start_id):
        return []

    sequences: List[ChainSequence] = []
    seen: set = set()

    for b in boundary_steps(path, start_id):
        step1 = StartLineMutation(method, b.path, "boundary", b.label)
        frontier = [(b.path, b.id_value, [b.label], [step1])]

        for _ in range(2, depth + 1):
            new_frontier = []
            for cur_path, cur_id, labels, steps in frontier:
                for s in structural_steps(cur_path, cur_id):
                    new_steps = steps + [StartLineMutation(method, s.path, "structural", s.label)]
                    new_labels = labels + [s.label]
                    sig = tuple((st.method, st.path) for st in new_steps)
                    if sig not in seen:
                        seen.add(sig)
                        sequences.append(ChainSequence(" → ".join(new_labels), new_steps))
                    new_frontier.append((s.path, s.id_value, new_labels, new_steps))
            frontier = new_frontier
            if not frontier:
                break

    return sequences


# ============================================================
# CLI / OUTPUT
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="IDOR Start-Line Permutator")
    ap.add_argument("xml")
    ap.add_argument("msg_id", type=int)
    ap.add_argument("--chain-depth", type=int, default=2)
    ap.add_argument("--format", choices=["text", "burp", "json"], default="text")
    args = ap.parse_args()

    az = IDORAnalyzer(args.xml)
    az.analyze()

    req = az.raw_messages[args.msg_id]["request"].splitlines()[0]
    method, path = req.split()[:2]

    candidates = az.get_candidates_for_msg(args.msg_id)
    if not candidates:
        return

    c = candidates[0]

    flat = generate_flat_mutations(method, path, c)
    chains = generate_chain_sequences(method, path, c, args.chain_depth)

    if args.format == "burp":
        for m in flat:
            print(f"{m.method} {m.path} HTTP/1.1")
        for ch in chains:
            print("")
            for s in ch.steps:
                print(f"{s.method} {s.path} HTTP/1.1")
        return

    if args.format == "json":
        print(json.dumps({
            "flat": [m.__dict__ for m in flat],
            "chains": [
                {"label": ch.label, "steps": [s.__dict__ for s in ch.steps]}
                for ch in chains
            ]
        }, indent=2))
        return

    # text
    for i, ch in enumerate(chains, 1):
        print(f"\n=== CHAIN {i}: {ch.label} ===")
        for j, s in enumerate(ch.steps, 1):
            print(f"Step {j}: {s.method} {s.path}")


if __name__ == "__main__":
    main()
