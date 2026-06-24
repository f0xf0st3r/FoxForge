import re
import shutil
import os
import subprocess
from urllib.parse import urlparse
import shlex

from modules.templates import (
    run_common_checks,
    run_vulnerability_templates,
    full_template_scan,
    format_report,
)


# ── Dependency checking ────────────────────────────────────────────────────────

WINDOWS_TOOL_PATHS = {
    'ffuf': [
        os.path.join(os.environ.get('ProgramFiles', ''), 'ffuf'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'ffuf'),
    ],
    'sqlmap': [
        os.path.join(os.environ.get('ProgramFiles', ''), 'sqlmap'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'sqlmap'),
    ],
}

INSTALL_COMMANDS = {
    'ffuf':   {'nt': 'Download binary from https://github.com/ffuf/ffuf/releases OR install Go first',
               'posix': 'sudo apt install ffuf'},
    'sqlmap': {'nt': 'pip install sqlmap',
               'posix': 'sudo apt install sqlmap'},
}

def is_tool_available(tool):
    """Check if a tool is available in PATH or common install directories."""
    if shutil.which(tool):
        return True
    if os.name == 'nt' and tool in WINDOWS_TOOL_PATHS:
        for path in WINDOWS_TOOL_PATHS[tool]:
            exe = os.path.join(path, f"{tool}.exe")
            if os.path.isfile(exe):
                os.environ['PATH'] = path + os.pathsep + os.environ.get('PATH', '')
                return True
    return False

def check_dependencies():
    """Warn the user about missing external tools (ffuf, sqlmap)."""
    tools = ['ffuf', 'sqlmap']
    missing = [tool for tool in tools if not is_tool_available(tool)]
    if missing:
        print(f"\n[!] Warning: The following tools are missing or not in PATH: {', '.join(missing)}")
        print("[!] Please install them using the commands below:\n")
        os_type = os.name
        for tool in missing:
            cmd = INSTALL_COMMANDS.get(tool, {}).get(os_type, 'Check official docs')
            print(f"  - {tool}: {cmd}")
        print("\n")


# ── Input validation ──────────────────────────────────────────────────────────

# Characters that could cause shell injection when passed to ffuf/sqlmap
_DANGEROUS_CHARS = re.compile(r'[;&|`$(){}!<>\\\n\r]')

def validate_target(raw_input):
    """
    Validates and normalises user-supplied target string.
    Returns (clean_url, None) on success, or (None, error_message) on failure.

    Checks performed:
      1. Empty / whitespace-only input
      2. Dangerous shell meta-characters
      3. Scheme must be http or https (or absent → auto-prepend http://)
      4. Hostname must be present after parsing
    """
    target = raw_input.strip()

    # 1 ── empty input
    if not target:
        return None, "Target cannot be empty."

    # 2 ── reject shell meta-characters (prevents injection into ffuf/sqlmap)
    if _DANGEROUS_CHARS.search(target):
        return None, "Target contains invalid characters."

    # 3 ── scheme check: auto-prepend http:// if missing, reject non-http schemes
    parsed = urlparse(target)

    if not parsed.scheme:
        target = "http://" + target
        parsed = urlparse(target)
    elif parsed.scheme not in ("http", "https"):
        return None, f"Unsupported scheme '{parsed.scheme}://'. Use http or https."

    # 4 ── hostname must exist after parsing
    if not parsed.hostname:
        return None, "Could not detect a valid hostname in the target."

    return target, None


# ── SQLMap target detection ────────────────────────────────────────────────────

def get_sqlmap_command(base_options: str = ""):
    """
    Collect URL, cookies and optional SQLMap arguments separately
    and build a safe SQLMap command string.
    """


    target = input("\nTarget URL: ").strip()

    if not target:
        print("[-] Target URL required.")
        return None

    parsed = urlparse(target)

    if not parsed.scheme or not parsed.netloc:
        print("[-] Invalid URL.")
        return None

    cookie = input(
        "Cookie (optional): "
    ).strip()

    extra_args = input(
        "Extra SQLMap options (optional): "
        "\nExamples:"
        "\n  -D dvwa"
        "\n  -D dvwa -T users"
        "\n  -D dvwa -T users --dump"
        "\n  --current-db --current-user"
        "\n\nEnter options: "
    ).strip()

    cmd = [
        "sqlmap",
        "-u",
        target,
        "--batch",
        "--random-agent"
    ]

    if base_options:
        cmd.extend(shlex.split(base_options))

    if cookie:
        cmd.extend([
            "--cookie",
            cookie
        ])

    if extra_args:
        cmd.extend(shlex.split(extra_args))

    return shlex.join(cmd)

def _save_to_workspace(executor, report_text, filename):
    """Write report_text into the workspace scans/ folder."""
    ws = executor.workspace
    if not ws.currentworkspace:
        print("  [!] No workspace active — output not saved.")
        return
    scan_dir = ws.getdirpath("scans")
    filepath = os.path.join(scan_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        print(f"  [+] Output saved to {filepath}")
        executor.logs.logexe(f"template_scan -> {filename}", "SUCCESS", filepath,
                             ws.getdirpath("logs"))
    except Exception as e:
        print(f"  [!] Error saving output: {e}")


def handle(executor):
    check_dependencies()

    while True:
        print("\nWEB SECURITY")

        print("\nDirectory Discovery")
        print("[1] Quick Enumeration")
        print("[2] Deep Enumeration")
        print("[3] Custom Wordlist Scan")

        print("\nSQL Analysis")
        print("[4] Basic SQL Testing")
        print("[5] Database Enumeration")
        print("[6] Full Assessment")

        print("\nTemplate Scanning")
        print("[7] Common Checks")
        print("[8] Vulnerability Templates")
        print("[9] Full Template Scan")

        print("\n[0] Go to Main Menu")

        try:
            ch = int(input("\nSelect from the available options: "))
        except ValueError:
            print("Invalid input! Please enter a valid number.")
            continue

        if ch == 0:
            break

        raw_target = input("Enter Target IP or Domain: ").strip()

        target, error = validate_target(raw_target)
        if error:
            print(f"[!] {error}")
            continue

        base_dir      = os.path.dirname(os.path.dirname(__file__))
        wordlistsmall = os.path.join(base_dir, "common.txt")
        wordlistlarge = os.path.join(base_dir, "medium.txt")

        
        if ch == 1:
            if not os.path.exists(wordlistsmall):
                print(f"\n[!] Default wordlist not found at {wordlistsmall}")
                user_input = input("Enter the path for your wordlist (or press Enter to skip): ").strip()
                if user_input:
                    wordlistsmall = user_input
            if os.path.exists(wordlistsmall):
                executor.run(
                    f"ffuf -u {target}/FUZZ -w {wordlistsmall}",
                    outputdir="scans",
                    outputfilename="ffuf_QuickEnumeration.txt"
                )
            else:
                print("\n[-] Invalid wordlist path. Skipping scan.")

        elif ch == 2:
            if not os.path.exists(wordlistlarge):
                print(f"\n[!] Default wordlist not found at {wordlistlarge}")
                user_input = input("Enter the path for your wordlist (or press Enter to skip): ").strip()
                if user_input:
                    wordlistlarge = user_input
            if os.path.exists(wordlistlarge):
                executor.run(
                    f"ffuf -u {target}/FUZZ -w {wordlistlarge}",
                    outputdir="scans",
                    outputfilename="ffuf_DeepEnumeration.txt"
                )
            else:
                print("\n[-] Invalid wordlist path. Skipping scan.")

        elif ch == 3:
            customlist = input("Enter the path for wordlist: ").strip()
            executor.run(
                f"ffuf -u {target}/FUZZ -w {customlist}",
                outputdir="scans",
                outputfilename="ffuf_CustomScan.txt"
            )

        elif ch == 4:
            cmd = get_sqlmap_command()

            if cmd:
                executor.run(
                    cmd,
                    outputdir="scans",
                    outputfilename="sqlmap_BasicTesting.txt"
                )

        elif ch == 5:
            cmd = get_sqlmap_command("--dbs")

            if cmd:
                executor.run(
                    cmd,
                    outputdir="scans",
                    outputfilename="sqlmap_DatabaseEnumeration.txt"
                )

        elif ch == 6:
            cmd = get_sqlmap_command(
                "--dbs --current-db --current-user --banner"
            )

            if cmd:
                executor.run(
                    cmd,
                    outputdir="scans",
            outputfilename="sqlmap_FullAssessment.txt"
        )

        elif ch == 7:
            findings = run_common_checks(target)
            report = format_report(common=findings, target=target)
            _save_to_workspace(executor, report, "template_common_checks.txt")

        elif ch == 8:
            findings = run_vulnerability_templates(target)
            report = format_report(vulns=findings, target=target)
            _save_to_workspace(executor, report, "template_vuln_headers.txt")

        elif ch == 9:
            results = full_template_scan(target)
            report = format_report(
                common=results["common"],
                vulns=results["vulns"],
                tech=results["tech"],
                target=target,
            )
            _save_to_workspace(executor, report, "template_full_scan.txt")

        else:
            print("[-] Invalid option.")
