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
UI_AUTOMATION_DIR_INIT = PROJECT_ROOT / "ui-automation"
UI_AUTOMATION_DIR_INIT.mkdir(exist_ok=True)

# ==========================================================
# NAVIGATION MODE
# ==========================================================

NAV_MODE = "project"  # "project" | "session" | "ui_automation"

def toggle_mode():
    global NAV_MODE
    modes = ["project", "session", "ui_automation"]
    current_idx = modes.index(NAV_MODE)
    NAV_MODE = modes[(current_idx + 1) % len(modes)]
    print(f"\n[*] Switched to {NAV_MODE.upper()} mode\n")

def browse_root() -> Path:
    if NAV_MODE == "project":
        return PROJECT_ROOT
    elif NAV_MODE == "session":
        return SESSIONS_DIR
    else:  # ui_automation
        return PROJECT_ROOT / "ui-automation"

# ==========================================================
# SAVED BOXES
# ==========================================================

PROJECT_SAVED_BOX: list[Path] = []
SESSION_SAVED_BOX: list[Path] = []
UI_AUTOMATION_SAVED_BOX: list[tuple[str, Path]] = []  # (user, path) tuples

def active_saved_box():
    if NAV_MODE == "project":
        return PROJECT_SAVED_BOX
    elif NAV_MODE == "session":
        return SESSION_SAVED_BOX
    else:  # ui_automation
        return UI_AUTOMATION_SAVED_BOX

def save(item: Path, user: str = None):
    if NAV_MODE == "ui_automation" and user:
        UI_AUTOMATION_SAVED_BOX.append((user, item))
    else:
        active_saved_box().append(item)

def show_saved_box():
    box = active_saved_box()

    if NAV_MODE == "project":
        label = "PROJECT"
    elif NAV_MODE == "session":
        label = "SESSION"
    else:
        label = "UI AUTOMATION"

    print(f"\n=== {label} SAVED BOX ===")

    if not box:
        print("(empty)")
    elif NAV_MODE == "ui_automation":
        # Group by user
        users = {}
        for user, path in box:
            if user not in users:
                users[user] = []
            users[user].append(path)

        for user, paths in users.items():
            print(f"\n----User {user}:")
            for i, path in enumerate(paths, 1):
                print(f"  [{i}] {path}")
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
    if NAV_MODE == "ui_automation":
        browse_sequences_tree()
        return

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
        "python3", str(SRC_DIR / "idor_permutator.py"),
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
            "python3", str(SRC_DIR / "idor_permutator.py"),
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
# UI AUTOMATION (PLAYWRIGHT)
# ==========================================================

UI_AUTOMATION_DIR = PROJECT_ROOT / "ui-automation"
SEQUENCES_FILE = UI_AUTOMATION_DIR / "sequences.json"
RECORDINGS_DIR = PROJECT_ROOT / "scripts" / "saved-sequences" / "recordings"
USERS_FILE = UI_AUTOMATION_DIR / "users.json"

def ensure_ui_automation_dirs():
    UI_AUTOMATION_DIR.mkdir(exist_ok=True)
    RECORDINGS_DIR.mkdir(exist_ok=True)
    if not SEQUENCES_FILE.exists():
        import json
        SEQUENCES_FILE.write_text(json.dumps({"sequences": []}, indent=2))
    if not USERS_FILE.exists():
        import json
        USERS_FILE.write_text(json.dumps({"users": []}, indent=2))

def load_sequences():
    import json
    if SEQUENCES_FILE.exists():
        return json.loads(SEQUENCES_FILE.read_text())
    return {"sequences": []}

def save_sequences(data):
    import json
    SEQUENCES_FILE.write_text(json.dumps(data, indent=2))

def load_users():
    import json
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return {"users": []}

def save_users(data):
    import json
    USERS_FILE.write_text(json.dumps(data, indent=2))

def configure_playwright_users():
    if NAV_MODE != "ui_automation":
        return

    ensure_ui_automation_dirs()
    data = load_users()

    print("\n=== Configure Playwright Users ===")
    print(f"Current users: {', '.join(data['users']) if data['users'] else '(none)'}\n")

    user_id = input("User ID (e.g., alice) or blank to cancel: ").strip()
    if not user_id:
        return

    if user_id in data['users']:
        print(f"\n[!] User {user_id} already exists.\n")
    else:
        data['users'].append(user_id)
        save_users(data)
        print(f"\n[+] User {user_id} configured.\n")

def list_playwright_sequences():
    if NAV_MODE != "ui_automation":
        return

    ensure_ui_automation_dirs()
    data = load_sequences()

    print("\n=== Playwright Sequences ===\n")

    if not data["sequences"]:
        print("(none)\n")
        return

    for seq in data["sequences"]:
        print(f"[{seq['id']}] {seq['name']}")
        print(f"  Description: {seq.get('description', '(none)')}")
        print(f"  Created: {seq.get('created', '(unknown)')}")
        print(f"  Actions: {len(seq.get('actions', []))}")
        if seq.get('recorded_by'):
            print(f"  Recorded by: {seq['recorded_by']}")
        print()

def browse_sequences_tree():
    if NAV_MODE != "ui_automation":
        return

    ensure_ui_automation_dirs()
    root = UI_AUTOMATION_DIR

    print(f"\n=== Browse UI Automation Tree ===")
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

        # Ask for user context
        users_data = load_users()
        if users_data['users']:
            print(f"\nAvailable users: {', '.join(users_data['users'])}")
            user = input("Which user owns this? ").strip() or "unknown"
        else:
            user = "unknown"

        save(path, user)
        print(f"\nSaved: {path} (User: {user})\n")
    except Exception:
        print("ERROR: Invalid selection.\n")

def execute_saved_sequence():
    if NAV_MODE != "ui_automation":
        return

    box = UI_AUTOMATION_SAVED_BOX

    if not box:
        print("\nUI AUTOMATION saved box is empty.\n")
        return

    print("\n=== Execute Saved Sequence ===")
    for i, (user, path) in enumerate(box, 1):
        print(f"[{i}] User {user}: {path}")

    try:
        idx = int(input("\nSelect sequence to execute: ").strip()) - 1
        original_user, path = box[idx]

        # Ask which user to execute as
        users_data = load_users()
        print(f"\nOriginal user: {original_user}")
        print(f"Available users: {', '.join(users_data['users'])}")
        exec_user = input("Execute as user (blank = original): ").strip() or original_user

        print(f"\n[*] Executing {path.name} as {exec_user}")
        print("[*] This would run: npx playwright test with this sequence")
        print(f"[*] Implementation: Add replay logic in {path}")
        print("\n[!] Note: Full execution requires Node.js Playwright integration\n")

    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")

def open_ui_sequence_in_codium():
    if NAV_MODE != "ui_automation":
        return

    box = UI_AUTOMATION_SAVED_BOX

    if not box:
        print("\nUI AUTOMATION saved box is empty.\n")
        return

    print("\n=== Open Sequence in Codium ===")
    for i, (user, path) in enumerate(box, 1):
        print(f"[{i}] User {user}: {path}")

    try:
        idx = int(input("\nSelect item to open: ").strip()) - 1
        user, path = box[idx]
        subprocess.run(["codium", str(path)], check=False)
        print(f"\n[+] Opened: {path} (User: {user})\n")
    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")
    except FileNotFoundError:
        print("ERROR: codium not found. Is it in PATH?\n")


# ==========================================================
# PLAYWRIGHT RECORDING → IDOR ANALYZER
# ==========================================================

def analyze_playwright_recording_for_idor():
    if NAV_MODE != "ui_automation":
        return

    import json

    ensure_ui_automation_dirs()

    # Get all recordings
    recordings = sorted(RECORDINGS_DIR.glob("*.json"))

    if not recordings:
        print("\nNo recordings found.\n")
        return

    print("\n=== Analyze Playwright Recording for IDORs ===\n")
    print("Available recordings:\n")

    for i, rec in enumerate(recordings, 1):
        try:
            data = json.loads(rec.read_text())
            user = data.get("user", "unknown")
            timestamp = data.get("timestamp", "unknown")
            num_actions = len(data.get("buckets", []))
            validation = data.get("validation", {})
            total_requests = validation.get("totalRequests", "?")
            print(f"[{i}] {rec.name}")
            print(f"    User: {user}, Actions: {num_actions}, Requests: {total_requests}")
        except Exception:
            print(f"[{i}] {rec.name} (error reading)")

    try:
        rec_idx = int(input("\nSelect recording: ").strip()) - 1
        selected_rec = recordings[rec_idx]
    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")
        return

    # Load recording using new JSON parser
    print(f"\n[*] Loading recording: {selected_rec.name}")

    try:
        # Use the Playwright JSON parser
        import sys
        sys.path.insert(0, str(SRC_DIR))
        from playwright_json_parser import PlaywrightRecording

        recording = PlaywrightRecording(str(selected_rec))
        buckets = recording.buckets

    except Exception as e:
        print(f"ERROR: Failed to load recording: {e}\n")
        return

    if not buckets:
        print("\nERROR: Recording has no action buckets.\n")
        return

    # Show actions
    print(f"\n=== Actions in {selected_rec.name} ===\n")

    for i, bucket in enumerate(buckets, 1):
        action = bucket.get("action", "(unnamed)")
        num_requests = len(bucket.get("requests", []))
        t_start = bucket.get("t_start_sec", 0)
        print(f"[{i}] {action}")
        print(f"    Requests: {num_requests}, Time: +{t_start}s")

    print("\n[a] Analyze all actions")
    print("[s] Select specific actions")

    choice = input("\nChoice: ").strip().lower()

    if choice == "a":
        selected_action_indices = list(range(len(buckets)))
    elif choice == "s":
        indices_str = input("Enter action numbers (comma-separated): ").strip()
        try:
            selected_action_indices = [int(x.strip()) - 1 for x in indices_str.split(",")]
            if not selected_action_indices or any(i < 0 or i >= len(buckets) for i in selected_action_indices):
                print("ERROR: Invalid action numbers.\n")
                return
        except (ValueError, IndexError):
            print("ERROR: Invalid action numbers.\n")
            return
    else:
        print("ERROR: Invalid choice.\n")
        return

    # Create output directory
    session_name = f"playwright_{recording.user}_{int(__import__('time').time())}"
    session_dir = SESSIONS_DIR / session_name
    input_dir = session_dir / "input"
    output_dir = session_dir / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save filtered recording as JSON (lossless)
    filtered_recording_json = input_dir / "recording.json"
    filtered_data = {
        "user": recording.user,
        "sequenceId": recording.sequence_id,
        "timestamp": recording.timestamp,
        "buckets": [buckets[i] for i in selected_action_indices],
        "validation": recording.validation
    }

    with open(filtered_recording_json, "w", encoding="utf-8") as f:
        json.dump(filtered_data, f, indent=2)

    print(f"\n[*] Saved filtered recording: {filtered_recording_json}")
    print(f"[*] Running IDOR analyzer on {len(selected_action_indices)} action(s)...")

    # Run analyzer with JSON input (new path)
    process = subprocess.Popen(
        ["python3", "-u", str(SRC_DIR / "idor_analyzer_json.py"), str(filtered_recording_json)],
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

    full_report = output_dir / "idor_playwright_analysis.txt"
    with open(full_report, "w", encoding="utf-8") as out:
        out.write("=== IDOR ANALYZER OUTPUT (Playwright Recording - JSON Direct) ===\n\n")
        out.write(f"Recording: {selected_rec.name}\n")
        out.write(f"User: {recording.user}\n")
        out.write(f"Actions analyzed: {len(selected_action_indices)}\n")
        out.write(f"Total requests: {sum(len(buckets[i].get('requests', [])) for i in selected_action_indices)}\n\n")
        out.write("".join(stdout_lines))
        if stderr_text:
            out.write("\n=== STDERR ===\n")
            out.write(stderr_text)

    print(f"\n[+] Analysis complete: {full_report}\n")


# ==========================================================
# CODIUM LAUNCHER
# ==========================================================

def open_in_codium():
    if NAV_MODE == "ui_automation":
        open_ui_sequence_in_codium()
        return

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
    elif NAV_MODE == "ui_automation":
        print("1) Configure Playwright users")
        print("2) List sequences")

    print("3) Browse tree & save path")

    if NAV_MODE == "session":
        print("4) Run IDOR analyzer")
        print("5) Dump raw HTTP history")
        print("6) Run IDOR permutator (single message)")
    elif NAV_MODE == "ui_automation":
        print("4) Execute saved sequence")
        print("5) Analyze recording for IDORs")

    print("c) Open saved item in Codium")
    print("m) Toggle navigation mode (project / session / ui_automation)")
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
            elif NAV_MODE == "ui_automation":
                configure_playwright_users()
        case "2":
            if NAV_MODE == "session":
                list_sessions()
            elif NAV_MODE == "ui_automation":
                list_playwright_sequences()
        case "3":
            browse_tree_and_save()
        case "4":
            if NAV_MODE == "session":
                run_analyzers_from_session()
            elif NAV_MODE == "ui_automation":
                execute_saved_sequence()
        case "5":
            if NAV_MODE == "session":
                dump_raw_http_from_session()
            elif NAV_MODE == "ui_automation":
                analyze_playwright_recording_for_idor()
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
