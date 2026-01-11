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
- boundary(+1) → structural(double_slash_before)
- Enumerated concretely and labeled algebraically
- Default chain depth = 2 (overrideable)

This script is downstream-only and read-only with respect to the analyzer.
"""

import sys
import re
import argparse
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
    
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


@dataclass(frozen=True)
class ChainStep:
    class_name: str        # boundary / structural
    label: str             # boundary(+1), structural(double_slash_before)
    path: str              # resulting path


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
]

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
    return any(x in (key or "").lower()
               for x in ("user", "account", "org", "tenant", "workspace",
                         "owner", "creator", "author"))


def requires_placeholder_only(c: IDCandidate) -> bool:
    return (
        c.token_bound or
        c.origin == "server" or
        is_identity_key(c.key) or
        c.id_value.startswith(("gid://", "urn:", "uuid:", "oid:"))
    )


# ============================================================
# PATH HELPERS
# ============================================================

def replace_id(path: str, old: str, new: str) -> str:
    if f"/{old}/" in path:
        return path.replace(f"/{old}/", f"/{new}/", 1)
    if path.endswith(f"/{old}"):
        return path[:-len(old)] + new
    return path.replace(old, new, 1)


def apply_structural_mutation(path: str, idv: str, kind: str) -> Optional[str]:
    if kind == "trailing_slash":
        return path + "/" if not path.endswith("/") else None
    if kind == "double_slash_before":
        return path.replace(f"/{idv}", f"//{idv}", 1)
    if kind == "double_slash_after":
        return path.replace(f"/{idv}/", f"/{idv}//", 1)
    if kind == "double_slash_wrap":
        return path.replace(f"/{idv}/", f"//{idv}//", 1)
    if kind == "dot_segment_after":
        return path.replace(f"/{idv}/", f"/{idv}/./", 1)
    if kind == "dot_segment_before":
        return path.replace(f"/{idv}", f"/./{idv}", 1)
    return None


# ============================================================
# PRIMITIVE STEP GENERATORS
# ============================================================

def boundary_steps(path: str, c: IDCandidate) -> List[ChainStep]:
    out = []
    if is_numeric_id(c.id_value):
        base = int(c.id_value)
        for o in BOUNDARY_OFFSETS:
            nv = str(base + o)
            out.append(ChainStep(
                "boundary",
                f"boundary({o:+d})",
                replace_id(path, c.id_value, nv)
            ))
        for b in BOUNDARY_ABSOLUTE:
            out.append(ChainStep(
                "boundary",
                f"boundary({b})",
                replace_id(path, c.id_value, b)
            ))
    return out


def structural_steps(path: str, c: IDCandidate) -> List[ChainStep]:
    out = []
    for k in STRUCTURAL_MUTATIONS:
        m = apply_structural_mutation(path, c.id_value, k)
        if m and m != path:
            out.append(ChainStep(
                "structural",
                f"structural({k})",
                m
            ))
    return out


# ============================================================
# CHAIN ENGINE (STATE TRANSITION GRAPH, DEPTH=2 DEFAULT)
# ============================================================

def generate_chain_mutations(
    method: str,
    path: str,
    candidate: IDCandidate,
    depth: int = 2
) -> List[StartLineMutation]:

    if depth < 2 or requires_placeholder_only(candidate):
        return []

    results: List[StartLineMutation] = []
    seen = set()

    first_steps = boundary_steps(path, candidate)

    for s1 in first_steps:
        second_steps = structural_steps(s1.path, candidate)
        for s2 in second_steps:
            label = f"{s1.label} → {s2.label}"
            key = (method, s2.path)
            if key in seen:
                continue
            seen.add(key)
            results.append(StartLineMutation(
                method=method,
                path=s2.path,
                mutation_class=f"chain:{s1.label}+{s2.label}",
                note=label
            ))

    return results


# ============================================================
# FLAT MUTATION ENGINE (UNCHANGED)
# ============================================================

def generate_mutations(method: str, path: str, c: IDCandidate) -> List[StartLineMutation]:
    if requires_placeholder_only(c):
        return [StartLineMutation(
            method,
            replace_id(path, c.id_value, PLACEHOLDER),
            "placeholder",
            "manual cross-user test"
        )]

    out: List[StartLineMutation] = []

    for s in boundary_steps(path, c):
        out.append(StartLineMutation(
            method,
            s.path,
            "boundary",
            s.label
        ))

    for s in structural_steps(path, c):
        out.append(StartLineMutation(
            method,
            s.path,
            "structural",
            s.label
        ))

    out.append(StartLineMutation(
        method,
        replace_id(path, c.id_value, PLACEHOLDER),
        "placeholder",
        "manual cross-user test"
    ))

    return out


# ============================================================
# CLI
# ============================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("msg_id", type=int)
    ap.add_argument("--chain-depth", type=int, default=2)
    args = ap.parse_args()

    az = IDORAnalyzer(args.xml)
    az.analyze()

    req_line = az.raw_messages[args.msg_id]["request"].splitlines()[0]
    method, path = req_line.split()[:2]

    candidates = az.get_candidates_for_msg(args.msg_id)
    if not candidates:
        return

    c = candidates[0]

    flat = generate_mutations(method, path, c)
    chained = generate_chain_mutations(method, path, c, args.chain_depth)

    for m in flat + chained:
        print(f"{m.method} {m.path}")
        if m.note:
            print(f"  # {m.note}")


if __name__ == "__main__":
    main()
