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
# NAVIGATION MODE
# ==========================================================

NAV_MODE = "project"  # "project" | "session"

def toggle_mode():
    global NAV_MODE
    NAV_MODE = "session" if NAV_MODE == "project" else "project"
    print(f"\n[*] Switched to {NAV_MODE.upper()} mode\n")

def browse_root() -> Path:
    return PROJECT_ROOT if NAV_MODE == "project" else SESSIONS_DIR

# ==========================================================
# SAVED BOXES
# ==========================================================

PROJECT_SAVED_BOX: list[Path] = []
SESSION_SAVED_BOX: list[Path] = []

def active_saved_box() -> list[Path]:
    return PROJECT_SAVED_BOX if NAV_MODE == "project" else SESSION_SAVED_BOX

def save(item: Path):
    active_saved_box().append(item)

def show_saved_box():
    box = active_saved_box()
    label = "PROJECT" if NAV_MODE == "project" else "SESSION"

    print(f"\n=== {label} SAVED BOX ===")
    if not box:
        print("(empty)")
    else:
        for i, item in enumerate(box, 1):
            print(f"[{i}] {item}")
    print()

def select_from_saved_box(prompt: str) -> Path | None:
    box = active_saved_box()
    show_saved_box()
    try:
        idx = int(input(prompt)) - 1
        return box[idx]
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

    SESSION_SAVED_BOX.append(history)
    SESSION_SAVED_BOX.append(sitemap)

    print(f"\nSession created: {session_name}")
    print("Input files:")
    print(f"  - {history}")
    print(f"  - {sitemap}")
    print("Saved to SESSION saved box.\n")

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
# TREE BROWSER (AESTHETIC DISPLAY + ABSOLUTE SAVE)
# ==========================================================

def browse_tree_and_save():
    root = browse_root()
    label = "PROJECT" if NAV_MODE == "project" else "SESSION"

    print(f"\n=== Browse {label} Tree ===")
    print(f"(root = {root})\n")

    def run_tree(cmd: list[str]) -> list[str]:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        return result.stdout.splitlines()

    try:
        pretty = run_tree(["tree", "--noreport", str(root)])
        absolute = run_tree(["tree", "-fi", "--noreport", str(root)])
    except FileNotFoundError:
        print("ERROR: 'tree' command not found.")
        print("Install with: sudo apt install tree\n")
        return

    # Empty tree is a valid state (e.g. no sessions yet)
    if not pretty or not absolute:
        print("(empty tree)\n")
        return

    if len(pretty) != len(absolute):
        print("ERROR: Tree output mismatch.\n")
        return

    for i, line in enumerate(pretty, 1):
        print(f"[{i}] {line}")

    try:
        idx = int(input("\nEnter number to save: ").strip()) - 1
        if idx < 0 or idx >= len(absolute):
            raise ValueError

        path = Path(absolute[idx])
        save(path)
        print(f"\nSaved: {path}\n")

    except ValueError:
        print("ERROR: Invalid selection.\n")

# ==========================================================
# ANALYZER EXECUTION (SESSION MODE ONLY)
# ==========================================================

def run_analyzers_from_session():
     session_dir = get_active_session_dir()
     input_dir = session_dir / "input"
     output_dir = session_dir / "output"
     output_dir.mkdir(parents=True, exist_ok=True)

     history = select_from_saved_box("history")
     sitemap = select_from_saved_box("sitemap")

     subprocess.run(
         ["python3", SRC_DIR / "idor_analyzer.py", history, sitemap],
         cwd=output_dir,
         check=True,
     )


    sitemap_tree_file = output_dir / "sitemap_tree.txt"
    with open(sitemap_tree_file, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", SRC_DIR / "sitemap_extractor.py", sitemap],
            stdout=f,
            check=True,
        )

    full_report = output_dir / "idor_full_analysis.txt"
    with open(full_report, "w", encoding="utf-8") as out:
        for fpath in sorted(output_dir.glob("idor_*.txt")):
            out.write(f"\n--- {fpath.name} ---\n")
            out.write(fpath.read_text())
        out.write("\n=== SITEMAP TREE ===\n")
        out.write(sitemap_tree_file.read_text())

    print("[+] Analysis complete.\n")

# ==========================================================
# MENU
# ==========================================================

def show_menu():
    print(f"\n=== {PROJECT_ROOT.name} IDOR INTERFACE ===")
    print(f"Mode: {NAV_MODE.upper()}\n")

    if NAV_MODE == "session":
        print("1) Create new session")
        print("2) List sessions")

    print("3) Browse tree & save path")

    if NAV_MODE == "session":
        print("4) Run IDOR analyzer")

    print("m) Toggle navigation mode (project / session)")
    print("s) Show saved box")
    print("q) Quit\n")

# ==========================================================
# MAIN LOOP
# ==========================================================

while True:
    show_menu()
    choice = input("> ").strip()

    match choice:
        case "1":
            if NAV_MODE == "session":
                create_session()
        case "2":
            if NAV_MODE == "session":
                list_sessions()
        case "3":
            browse_tree_and_save()
        case "4":
            if NAV_MODE == "session":
                run_analyzers_from_session()
        case "m" | "M":
            toggle_mode()
        case "s" | "S":
            show_saved_box()
        case "q" | "Q":
            print("Exiting.")
            sys.exit(0)
        case _:
            print("Invalid option.\n")
