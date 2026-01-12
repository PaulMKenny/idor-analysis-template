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
# SAVED BOXES (UNCHANGED)
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
# TREE BROWSER (UNCHANGED)
# ==========================================================

def browse_tree_and_save():
    root = browse_root()
    label = "PROJECT" if NAV_MODE == "project" else "SESSION"

    print(f"\n=== Browse {label} Tree ===")
    print(f"(root = {root})\n")

    def run_tree(cmd):
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.stdout.splitlines()

    try:
        pretty = run_tree(["tree", "--noreport", str(root)])
        absolute = run_tree(["tree", "-fi", "--noreport", str(root)])
    except FileNotFoundError:
        print("ERROR: 'tree' command not found.")
        return

    if not pretty or not absolute:
        print("(empty tree)\n")
        return

    for i, line in enumerate(pretty, 1):
        print(f"[{i}] {line}")

    try:
        idx = int(input("\nEnter number to save: ").strip()) - 1
        path = Path(absolute[idx])
        save(path)
        print(f"\nSaved: {path}\n")
    except Exception:
        print("ERROR: Invalid selection.\n")

# ==========================================================
# SESSION-SCOPED XML SELECTION
# ==========================================================

def select_xml_from_session_input(session_root: Path, label: str) -> Path | None:
    input_dir = session_root / "input"

    if not input_dir.is_dir():
        print("ERROR: Session input directory missing.\n")
        return None

    xmls = sorted(p for p in input_dir.iterdir() if p.is_file() and p.suffix == ".xml")

    if not xmls:
        print("ERROR: No XML files found in session input.\n")
        return None

    print(f"\n=== Select {label} XML ===")
    for i, p in enumerate(xmls, 1):
        print(f"[{i}] {p.name}")

    try:
        idx = int(input("> ").strip()) - 1
        return xmls[idx]
    except Exception:
        print("ERROR: Invalid selection.\n")
        return None

# ==========================================================
# Raw transaction dump option
# ==========================================================

def dump_raw_http_from_session():
    if NAV_MODE != "session":
        return

    print("\n=== Dump Raw HTTP History (Session Mode) ===\n")

    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available.\n")
        return

    session_root = sessions[-1]  # most recent session
    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history = select_xml_from_session_input(session_root, "history")
    if not history:
        return

    raw_dump_file = output_dir / "raw_http_dump.txt"

    with open(raw_dump_file, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", str(SRC_DIR / "raw_http_dump.py"), str(history)],
            stdout=f,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    print("[+] Raw HTTP history written to:")
    print(f"    {raw_dump_file}\n")

# ==========================================================
# Run analyzer
# ==========================================================

def run_analyzers_from_session():
    if NAV_MODE != "session":
        return

    print("\n=== Run IDOR Analyzer (Session Mode) ===\n")

    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available.\n")
        return

    session_root = sessions[-1]
    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history = select_xml_from_session_input(session_root, "history")
    sitemap = select_xml_from_session_input(session_root, "sitemap")

    if not history or not sitemap:
        return

    process = subprocess.Popen(
        ["python3", "-u", str(SRC_DIR / "idor_analyzer.py"), str(history), str(sitemap)],
        cwd=str(output_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_lines = []
    for line in process.stdout:
        print(line, end="", flush=True)
        stdout_lines.append(line)
    process.wait()
    stderr_text = process.stderr.read()
    if stderr_text:
        print(stderr_text, file=sys.stderr)

    class Result:
        stdout = "".join(stdout_lines)
        stderr = stderr_text
    result = Result()

    sitemap_tree = output_dir / "sitemap_tree.txt"
    with open(sitemap_tree, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", str(SRC_DIR / "sitemap_extractor.py"), str(sitemap)],
            stdout=f,
            check=True,
        )

    full_report = output_dir / "idor_full_analysis.txt"
    with open(full_report, "w", encoding="utf-8") as out:
        out.write("=== IDOR ANALYZER OUTPUT ===\n\n")
        out.write(result.stdout)
        if result.stderr:
            out.write("\n=== STDERR ===\n")
            out.write(result.stderr)
        out.write("\n\n=== SITEMAP TREE ===\n")
        out.write(sitemap_tree.read_text(encoding="utf-8"))

    print("[+] Analysis complete.\n")

# ==========================================================
# Run permutator (single message) + chain depth (default 2)
# ==========================================================

def run_permutator_from_session():
    if NAV_MODE != "session":
        return

    print("\n=== IDOR Start-Line Permutator ===\n")

    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available.\n")
        return

    session_root = sessions[-1]
    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history = select_xml_from_session_input(session_root, "history")
    if not history:
        return

    msg_id = input("Enter message ID: ").strip()
    if not msg_id.isdigit():
        print("ERROR: Message ID must be numeric.\n")
        return

    fmt = input("Output format [text/burp/json] (default: text): ").strip() or "text"

    chain_depth_raw = input("Chain depth for full output (default: 2): ").strip()
    chain_depth = 2
    if chain_depth_raw:
        if not chain_depth_raw.isdigit() or int(chain_depth_raw) < 1:
            print("ERROR: chain depth must be a positive integer.\n")
            return
        chain_depth = int(chain_depth_raw)

    single_file = output_dir / f"permutations_msg{msg_id}_single.txt"
    chained_file = output_dir / f"permutations_msg{msg_id}_chained.txt"

    # === PASS 1: Single mutations (immediate) ===
    print("\n[*] Generating single mutations...")
    
    cmd_single = [
        "python3", "-u", str(SRC_DIR / "idor_permutator.py"),
        str(history), msg_id,
        "--format", fmt,
        "--chain-depth", "1",
    ]

    process = subprocess.Popen(
        cmd_single,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout_lines = []
    for line in process.stdout:
        print(line, end="", flush=True)
        stdout_lines.append(line)
    process.wait()
    stderr_text = process.stderr.read()
    if stderr_text:
        print(stderr_text)

    with open(single_file, "w", encoding="utf-8") as f:
        f.write("".join(stdout_lines))

    print(f"\n[+] Single mutations: {single_file}")
    print("[*] You can start testing now.\n")

    # === PASS 2: Chained mutations (if chain_depth > 1) ===
    if chain_depth > 1:
        print(f"[*] Generating chained mutations (depth={chain_depth})...")
        
        cmd_chained = [
            "python3", "-u", str(SRC_DIR / "idor_permutator.py"),
            str(history), msg_id,
            "--format", fmt,
            "--chain-depth", str(chain_depth),
        ]

        process = subprocess.Popen(
            cmd_chained,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout_lines = []
        for line in process.stdout:
            stdout_lines.append(line)
            # Don't print chained - just save
        process.wait()
        stderr_text = process.stderr.read()

        with open(chained_file, "w", encoding="utf-8") as f:
            f.write("".join(stdout_lines))
            if stderr_text:
                f.write("\n=== STDERR ===\n")
                f.write(stderr_text)

        print(f"[+] Chained mutations: {chained_file}")

    print()


# ==========================================================
# CODIUM LAUNCHER
# ==========================================================

def open_in_codium():
    box = active_saved_box()
    label = "PROJECT" if NAV_MODE == "project" else "SESSION"

    if not box:
        print(f"\n{label} saved box is empty.\n")
        return

    print(f"\n=== Open in Codium ({label}) ===")
    for i, item in enumerate(box, 1):
        print(f"[{i}] {item}")

    try:
        idx = int(input("\nSelect item to open: ").strip()) - 1
        path = box[idx]
        subprocess.run(["codium", str(path)], check=False)
        print(f"\n[+] Opened: {path}\n")
    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")
    except FileNotFoundError:
        print("ERROR: codium not found. Is it in PATH?\n")

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
        print("5) Dump raw HTTP history")
        print("6) Run IDOR permutator (single message)")

    print("c) Open saved item in Codium")
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
        case "5":
            if NAV_MODE == "session":
                dump_raw_http_from_session()
        case "6":
            if NAV_MODE == "session":
                run_permutator_from_session()
        case "s" | "S":
            show_saved_box()
        case "c" | "C":
            open_in_codium()
        case "m" | "M":
            toggle_mode()
        case "q" | "Q":
            print("Exiting.")
            sys.exit(0)
        case _:
            print("Invalid option.\n")
