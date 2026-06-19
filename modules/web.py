import shutil
import os
import subprocess

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
    'ffuf': {'nt': 'Download binary from https://github.com/ffuf/ffuf/releases OR install Go first', 'posix': 'sudo apt install ffuf'},
    'sqlmap': {'nt': 'pip install sqlmap', 'posix': 'sudo apt install sqlmap'},
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


def handle(executor):
    while True:
        check_dependencies()
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

        print("[0] Go to Main Menu")

        try:
            ch = int(input("Select from the available options : "))
        except ValueError:
            print("Invalid input! Please enter a valid number.")
            continue

        if ch == 0:
            break

        target = input("Enter Target IP or Domain: ").strip()
        if not target:
            print("Enter a valid target..")
            continue


        base_dir = os.path.dirname(os.path.dirname(__file__))
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
                    outputdir = "scans",
                    outputfilename = "ffuf_QuickEnumeration.txt"
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
                    outputdir = "scans",
                    outputfilename = "ffuf_DeepEnumeration.txt"
                )
            else:
                print("\n[-] Invalid wordlist path. Skipping scan.")

        elif ch == 3:
            customlist = input("Enter the path for wordlist : ").strip()
            executor.run(
                f"ffuf -u {target}/FUZZ -w {customlist}",
                outputdir = "scans",
                outputfilename = "ffuf_CustomScan.txt"
            )
        
        elif ch == 4:
            executor.run(
                f"sqlmap -u {target} --batch",
                outputdir = "scans",
                outputfilename = "sqlmap_BasicTesting.txt"
            )

            
            





