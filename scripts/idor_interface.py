# ==========================================================
# SESSION SELECTION (CENTRALIZED)
# ==========================================================

def select_session() -> Path | None:
    """Select a session by number. Returns session root path."""
    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available.\n")
        return None

    print("\n=== Select Session ===")
    for i, s in enumerate(sessions, 1):
        print(f"[{i}] {s.name}")

    try:
        idx = int(input("> ").strip()) - 1
        return sessions[idx]
    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")
        return None


def get_session_files(session_root: Path) -> tuple[Path | None, Path | None]:
    """Get history and sitemap files from session input dir."""
    input_dir = session_root / "input"
    if not input_dir.is_dir():
        return None, None
    
    history = None
    sitemap = None
    
    for f in input_dir.iterdir():
        if f.is_file() and f.suffix == ".xml":
            if f.name.startswith("history_"):
                history = f
            elif f.name.startswith("sitemap_"):
                sitemap = f
    
    return history, sitemap


# ==========================================================
# Run analyzer (simplified)
# ==========================================================

def run_analyzer():
    if NAV_MODE != "session":
        return

    print("\n=== Run IDOR Analyzer ===\n")

    session_root = select_session()
    if not session_root:
        return

    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history, sitemap = get_session_files(session_root)

    if not history:
        print("ERROR: No history_*.xml found in session input.\n")
        return
    if not sitemap:
        print("ERROR: No sitemap_*.xml found in session input.\n")
        return

    print(f"[*] Session: {session_root.name}")
    print(f"[*] History: {history.name}")
    print(f"[*] Sitemap: {sitemap.name}\n")

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

    full_report = output_dir / "idor_full_analysis.txt"
    with open(full_report, "w", encoding="utf-8") as out:
        out.write("=== IDOR ANALYZER OUTPUT ===\n\n")
        out.write("".join(stdout_lines))
        if stderr_text:
            out.write("\n=== STDERR ===\n")
            out.write(stderr_text)

    print(f"\n[+] Analysis complete: {session_root.name}\n")


# ==========================================================
# Run sitemap extractor (separate command)
# ==========================================================

def run_sitemap_extractor():
    if NAV_MODE != "session":
        return

    print("\n=== Run Sitemap Extractor ===\n")

    session_root = select_session()
    if not session_root:
        return

    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    _, sitemap = get_session_files(session_root)

    if not sitemap:
        print("ERROR: No sitemap_*.xml found in session input.\n")
        return

    print(f"[*] Session: {session_root.name}")
    print(f"[*] Sitemap: {sitemap.name}\n")

    sitemap_tree = output_dir / "sitemap_tree.txt"
    with open(sitemap_tree, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", str(SRC_DIR / "sitemap_extractor.py"), str(sitemap)],
            stdout=f,
            check=True,
        )

    print(f"[+] Sitemap tree written to: {sitemap_tree}\n")


# ==========================================================
# Dump raw HTTP history (simplified)
# ==========================================================

def dump_raw_http():
    if NAV_MODE != "session":
        return

    print("\n=== Dump Raw HTTP History ===\n")

    session_root = select_session()
    if not session_root:
        return

    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history, _ = get_session_files(session_root)

    if not history:
        print("ERROR: No history_*.xml found in session input.\n")
        return

    print(f"[*] Session: {session_root.name}")
    print(f"[*] History: {history.name}\n")

    raw_dump_file = output_dir / "raw_http_dump.txt"

    with open(raw_dump_file, "w", encoding="utf-8") as f:
        subprocess.run(
            ["python3", str(SRC_DIR / "raw_http_dump.py"), str(history)],
            stdout=f,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    print(f"[+] Raw HTTP history written to: {raw_dump_file}\n")


# ==========================================================
# Run permutator (simplified)
# ==========================================================

def run_permutator():
    if NAV_MODE != "session":
        return

    print("\n=== IDOR Start-Line Permutator ===\n")

    session_root = select_session()
    if not session_root:
        return

    output_dir = session_root / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    history, _ = get_session_files(session_root)

    if not history:
        print("ERROR: No history_*.xml found in session input.\n")
        return

    print(f"[*] Session: {session_root.name}")
    print(f"[*] History: {history.name}\n")

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
# Repeat session (simplified)
# ==========================================================

def repeat_session():
    if NAV_MODE != "session":
        return

    print("\n=== Repeat Session (Copy Inputs) ===\n")

    sessions = sorted(p for p in SESSIONS_DIR.iterdir() if p.is_dir())
    if not sessions:
        print("ERROR: No sessions available to repeat.\n")
        return

    # Show base sessions only (not runs)
    base_sessions = [s for s in sessions if "-run_" not in s.name]
    
    print("Select session to repeat:")
    for i, s in enumerate(base_sessions, 1):
        print(f"[{i}] {s.name}")

    try:
        idx = int(input("> ").strip()) - 1
        source_session = base_sessions[idx]
    except (ValueError, IndexError):
        print("ERROR: Invalid selection.\n")
        return

    base_name = source_session.name

    # Find next available run number
    existing_runs = [1]
    for s in sessions:
        if s.name.startswith(f"{base_name}-run_"):
            try:
                run_num = int(s.name.split("-run_")[1])
                existing_runs.append(run_num)
            except (ValueError, IndexError):
                pass
    
    new_run = max(existing_runs) + 1
    new_session_name = f"{base_name}-run_{new_run}"
    new_session_root = SESSIONS_DIR / new_session_name
    new_input_dir = new_session_root / "input"
    new_output_dir = new_session_root / "output"

    new_input_dir.mkdir(parents=True)
    new_output_dir.mkdir(parents=True)

    source_input_dir = source_session / "input"
    if not source_input_dir.is_dir():
        print(f"ERROR: Source session has no input directory.\n")
        return

    import shutil
    copied_files = []
    for f in source_input_dir.iterdir():
        if f.is_file() and f.suffix == ".xml":
            dest = new_input_dir / f.name
            shutil.copy2(f, dest)
            copied_files.append(f.name)

    print(f"\n[+] Created {new_session_name}")
    print(f"[+] Copied {len(copied_files)} input files:")
    for name in copied_files:
        print(f"    {name}")
    print(f"\n[*] Ready to run analyzer on {new_session_name}\n")


# ==========================================================
# MENU (updated)
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
        print("5) Run sitemap extractor")
        print("6) Dump raw HTTP history")
        print("7) Run IDOR permutator")
        print("8) Repeat session (copy inputs)")

    print("c) Open saved item in Codium")
    print("m) Toggle navigation mode (project / session)")
    print("s) Show saved box")
    print("q) Quit\n")


# ==========================================================
# MAIN LOOP (updated)
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
                run_analyzer()
        case "5":
            if NAV_MODE == "session":
                run_sitemap_extractor()
        case "6":
            if NAV_MODE == "session":
                dump_raw_http()
        case "7":
            if NAV_MODE == "session":
                run_permutator()
        case "8":
            if NAV_MODE == "session":
                repeat_session()
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
