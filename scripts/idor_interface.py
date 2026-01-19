#!/usr/bin/env python3
import os
import sys
import subprocess
import re
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
# DIFF MODULE: User A vs User B comparison with token renewal
# ==========================================================

def select_session_from_menu(label: str) -> Path | None:
    """Select a session from interactive menu."""
    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available.\n")
        return None

    print(f"\n=== Select {label} session ===")
    for i, s in enumerate(sessions, 1):
        print(f"[{i}] {s.name}")

    try:
        idx = int(input("> ").strip()) - 1
        return sessions[idx]
    except Exception:
        print("ERROR: Invalid selection.\n")
        return None


def _parse_request_line(first_line: str) -> tuple[str, str]:
    """Parse HTTP request line to extract method and path."""
    parts = first_line.strip().split()
    if len(parts) < 2:
        return "", ""
    return parts[0].upper(), parts[1]


def _parameterize_path(path: str) -> str:
    """
    Replace numeric/hex IDs in path with {id} placeholders.
    Example: /api/users/1234/profile -> /api/users/{id}/profile
    """
    if "?" in path:
        base, query = path.split("?", 1)
        q = "?" + query
    else:
        base, q = path, ""

    segs = base.split("/")
    n = 0
    for i, seg in enumerate(segs):
        # Match 4+ digit numbers or 16+ hex strings (UUIDs)
        if re.fullmatch(r"\d{4,}", seg) or re.fullmatch(r"[0-9a-fA-F]{16,}", seg):
            n += 1
            segs[i] = "{id}" if n == 1 else f"{{id{n}}}"
    return "/".join(segs) + q


def _normalize_path_for_match(path: str) -> str:
    """Normalize path for matching across sessions."""
    p = _parameterize_path(path)
    # Apply regex substitution for any remaining IDs
    p = re.sub(r"\b\d{4,}\b", "{id}", p)
    p = re.sub(r"\b[0-9a-fA-F]{16,}\b", "{id}", p)
    return p


def _get_raw_request_by_msg_id(history_xml: Path, msg_id: int) -> bytes | None:
    """Get raw HTTP request bytes for a specific message ID."""
    sys.path.insert(0, str(SRC_DIR))
    from idor_analyzer import iter_http_messages

    for mid, raw_req, _ in iter_http_messages(str(history_xml)):
        if mid == msg_id:
            return raw_req
    return None


def _find_matching_request(history_xml: Path, method: str, norm_path: str):
    """Find a request in history matching the method and normalized path."""
    sys.path.insert(0, str(SRC_DIR))
    from idor_analyzer import iter_http_messages, split_http_message

    for mid, raw_req, _ in iter_http_messages(str(history_xml)):
        first, _, _ = split_http_message(raw_req)
        m, p = _parse_request_line(first)
        if m == method and _normalize_path_for_match(p) == norm_path:
            return mid, raw_req
    return None


def _build_curl(url: str, method: str, headers: dict, body: bytes) -> str:
    """Build a curl command from request components."""
    skip = {"host", "content-length"}

    lines = [f"curl -X {method} '{url}' \\"]
    for k, v in headers.items():
        if k in skip:
            continue
        lines.append(f"  -H '{k}: {v}' \\")

    if body:
        lines.append("  --data-binary @- <<'EOF'")
        lines.append(body.decode(errors="replace"))
        lines.append("EOF")
    else:
        lines[-1] = lines[-1].rstrip("\\")

    return "\n".join(lines)


def configure_session_login():
    """Configure login flow for a session (for token renewal)."""
    if NAV_MODE != "session":
        return

    session = select_session_from_menu("Configure login for")
    if not session:
        return

    sys.path.insert(0, str(SRC_DIR))
    from session_renewer import SessionRenewer

    renewer = SessionRenewer(session)
    renewer.configure_login_flow()


def run_userA_userB_replay_diff():
    """
    Main diff module workflow: Compare User A vs User B requests
    with optional token renewal.
    """
    if NAV_MODE != "session":
        return

    # Select sessions
    session_a = select_session_from_menu("User A")
    session_b = select_session_from_menu("User B")
    if not session_a or not session_b:
        return

    # Select history files
    history_a = select_xml_from_session_input(session_a, "User A history")
    history_b = select_xml_from_session_input(session_b, "User B history")
    if not history_a or not history_b:
        return

    # Get message ID to compare
    try:
        msg_id = int(input("Enter candidate msg_id: ").strip())
    except ValueError:
        print("ERROR: Invalid message ID\n")
        return

    # Get User A's request
    sys.path.insert(0, str(SRC_DIR))
    from idor_analyzer import split_http_message
    from session_renewer import select_token_refresh_mode, SessionRenewer, merge_fresh_tokens

    raw_a = _get_raw_request_by_msg_id(history_a, msg_id)
    if not raw_a:
        print("ERROR: msg_id not found in User A session\n")
        return

    a_first, a_hdrs, a_body = split_http_message(raw_a)
    method, path = _parse_request_line(a_first)
    norm = _normalize_path_for_match(path)

    # Find matching request in User B's history
    match = _find_matching_request(history_b, method, norm)
    if not match:
        print("ERROR: No matching User B request\n")
        print(f"Looked for: {method} {norm}\n")
        return

    _, raw_b = match
    _, b_hdrs, _ = split_http_message(raw_b)

    # Token renewal workflow
    print("\n[*] Found matching request in User B session")
    print(f"[*] User B tokens from XML may be stale\n")

    mode = select_token_refresh_mode()

    fresh_tokens = None
    if mode == "playwright":
        renewer = SessionRenewer(session_b)

        # Check if config exists
        if not renewer.config:
            print("\n[!] No login configuration found for User B session.")
            print("[!] Run menu option 7 first to configure login flow.\n")
            fallback = input("Continue with manual token entry? [y/N]: ").strip().lower()
            if fallback == 'y':
                fresh_tokens = renewer.get_fresh_tokens_manual()
        else:
            # Ask headless vs headed
            headless_choice = input("Run browser in headless mode? [Y/n]: ").strip().lower()
            headless = headless_choice != 'n'
            fresh_tokens = renewer.get_fresh_tokens_playwright(headless=headless)

    elif mode == "manual":
        renewer = SessionRenewer(session_b)
        fresh_tokens = renewer.get_fresh_tokens_manual()

    # Merge headers
    merged_hdrs = dict(b_hdrs)

    # Always prefer User A's content-type and accept
    for k in ("content-type", "accept"):
        if k in a_hdrs:
            merged_hdrs[k] = a_hdrs[k]

    # Merge fresh tokens if available
    if fresh_tokens:
        merged_hdrs = merge_fresh_tokens(merged_hdrs, fresh_tokens)

    # Build curl command
    host = merged_hdrs.get("host")
    url = f"https://{host}{path}"

    curl = _build_curl(url, method, merged_hdrs, a_body)
    param = f"{method} {_parameterize_path(path)}"

    # Write output
    out = session_b / "output"
    out.mkdir(exist_ok=True)
    out_file = out / f"replay_diff_msg_{msg_id}.txt"

    with open(out_file, "w") as f:
        f.write("=== CURL ===\n")
        f.write(curl + "\n\n")
        f.write("=== PARAMETERIZED ===\n")
        f.write(param + "\n")
        f.write("\n=== NOTES ===\n")
        f.write(f"User A session: {session_a.name}\n")
        f.write(f"User B session: {session_b.name}\n")
        f.write(f"Message ID: {msg_id}\n")
        f.write(f"Token refresh mode: {mode}\n")

    print(f"\n[+] Written {out_file}")
    print("[*] You can now execute this curl command to test for IDOR\n")

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
        print("7) Configure login flow (for token renewal)")
        print("8) User A vs User B diff + replay (with token renewal)")

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
        case "7":
            if NAV_MODE == "session":
                configure_session_login()
        case "8":
            if NAV_MODE == "session":
                run_userA_userB_replay_diff()
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
