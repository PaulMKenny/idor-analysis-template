#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path

# ==========================================================
# PROJECT ROOT BOOTSTRAP + LOCK
# ==========================================================

def find_or_create_project_root(start: Path) -> Path:
    cur = start.resolve()

    while cur != cur.parent:
        if (cur / ".project_root").is_file():
            return cur
        cur = cur.parent

    root = start.resolve()
    (root / ".project_root").touch()
    (root / "sessions").mkdir(exist_ok=True)

    print("=== IDOR PROJECT INITIALIZED ===")
    print(f"Root: {root}")
    print("Created:")
    print("  .project_root")
    print("  sessions/")
    print("===============================")
    print()

    return root


PROJECT_ROOT = find_or_create_project_root(Path.cwd())
os.chdir(PROJECT_ROOT)

SESSIONS_DIR = PROJECT_ROOT / "sessions"
SRC_DIR = PROJECT_ROOT / "src"

# ==========================================================
# SAVED BOX — MULTI-ITEM CLIPBOARD
# ==========================================================

SAVED_BOX: list[Path] = []

def save(item: Path):
    SAVED_BOX.append(item)

def show_saved_box():
    print("\n=== Saved Box ===")
    if not SAVED_BOX:
        print("(empty)")
    else:
        for i, item in enumerate(SAVED_BOX, 1):
            print(f"[{i}] {item}")
    print()

def select_from_saved_box(prompt: str) -> Path | None:
    show_saved_box()
    try:
        idx = int(input(prompt)) - 1
        return SAVED_BOX[idx]
    except Exception:
        print("ERROR: Invalid selection.\n")
        return None

# ==========================================================
# SESSION MANAGEMENT
# ==========================================================

def create_session():
    print("\n=== Create New Session ===")
    idx = input("Enter session index (number): ").strip()

    if not idx.isdigit():
        print("ERROR: Session index must be numeric.\n")
        return

    session_name = f"session_{idx}"
    session_root = SESSIONS_DIR / session_name
    input_dir = session_root / "input"
    output_dir = session_root / "output"

    if session_root.exists():
        print(f"ERROR: {session_name} already exists.\n")
        return

    input_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)

    history = input_dir / f"history_{idx}.xml"
    sitemap = input_dir / f"sitemap_{idx}.xml"

    history.touch()
    sitemap.touch()

    save(history)
    save(sitemap)

    print(f"\nSession created: {session_name}")
    print("Input files:")
    print(f"  - {history}")
    print(f"  - {sitemap}")
    print("Saved to Saved Box.\n")

def list_sessions():
    print("\n=== Existing Sessions ===\n")
    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("(none)\n")
        return
    for s in sessions:
        print(f"- {s.name}")
    print()

# ==========================================================
# TREE BROWSER (SESSION INPUT)
# ==========================================================

def browse_tree_and_save():
    print("\n=== Browse Project Tree ===\n")

    paths = []
    for root, _, files in os.walk(SESSIONS_DIR):
        for f in files:
            paths.append(Path(root) / f)

    if not paths:
        print("(no files)\n")
        return

    for i, p in enumerate(paths, 1):
        print(f"[{i}] {p}")

    try:
        idx = int(input("\nEnter number to save: ")) - 1
        save(paths[idx])
        print(f"\nSaved: {paths[idx]}\n")
    except Exception:
        print("ERROR: Invalid selection.\n")

# ==========================================================
# ANALYZER EXECUTION (Messages 6–9)
# ==========================================================

def run_analyzers_from_session():
    print("\n=== Run IDOR Analyzer (Session) ===\n")

    history = select_from_saved_box("Select history XML #: ")
    sitemap = select_from_saved_box("Select sitemap XML #: ")

    if not history or not sitemap:
        return

    session_root = history.parents[2]
    output_dir = session_root / "output"

    print(f"\n[*] Running analyzers for {session_root.name}")
    print(f"[*] Output dir: {output_dir}\n")

    # --- IDOR ANALYZER ---
    subprocess.run(
        [
            "python3",
            SRC_DIR / "idor_analyzer.py",
            history,
            sitemap,
        ],
        cwd=output_dir,
        check=True,
    )

    # --- SITEMAP EXTRACTOR ---
    sitemap_tree_file = output_dir / "sitemap_tree.txt"
    with open(sitemap_tree_file, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", SRC_DIR / "sitemap_extractor.py", sitemap],
            stdout=f,
            check=True,
        )

    # --- COLLATION (Message 7) ---
    full_report = output_dir / "idor_full_analysis.txt"
    with open(full_report, "w", encoding="utf-8") as out:
        out.write("=== IDOR ANALYSIS ===\n\n")
        for f in output_dir.glob("idor_*.txt"):
            out.write(f"\n--- {f.name} ---\n")
            out.write(f.read_text())

        out.write("\n\n=== SITEMAP TREE ===\n\n")
        out.write(sitemap_tree_file.read_text())

    print("[+] Analysis complete.")
    print(f"    - {full_report}")
    print()

# ==========================================================
# MENU
# ==========================================================

MENU = f"""
=== {PROJECT_ROOT.name} IDOR INTERFACE ===

1) Create new session
2) List sessions
3) Browse tree & save input
4) Run IDOR analyzer (session)
s) Show saved box
q) Quit
"""

# ==========================================================
# MAIN LOOP
# ==========================================================

while True:
    print(MENU)
    choice = input("> ").strip()

    match choice:
        case "1":
            create_session()
        case "2":
            list_sessions()
        case "3":
            browse_tree_and_save()
        case "4":
            run_analyzers_from_session()
        case "s" | "S":
            show_saved_box()
        case "q" | "Q":
            print("Exiting.")
            sys.exit(0)
        case _:
            print("Invalid option.\n")
