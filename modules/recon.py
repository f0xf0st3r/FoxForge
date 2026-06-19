import shutil
import os
import subprocess

# Common install paths on Windows where tools may not be in PATH
WINDOWS_TOOL_PATHS = {
    'nmap': [
        os.path.join(os.environ.get('ProgramFiles', ''), 'Nmap'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Nmap'),
    ],
}

INSTALL_COMMANDS = {
    'nmap': {'nt': 'winget install Insecure.Nmap', 'posix': 'sudo apt install nmap'},
    'whatweb': {'nt': 'Ruby required: gem install whatweb (or use WSL)', 'posix': 'sudo apt install whatweb'},
    'httpx': {'nt': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
              'posix': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'},
}

def is_tool_available(tool):
    """Check if a tool is available in PATH or common install directories."""
    if shutil.which(tool):
        return True
    # On Windows, also check common install directories
    if os.name == 'nt' and tool in WINDOWS_TOOL_PATHS:
        for path in WINDOWS_TOOL_PATHS[tool]:
            exe = os.path.join(path, f"{tool}.exe")
            if os.path.isfile(exe):
                # Add to PATH for this session so executor can find it
                os.environ['PATH'] = path + os.pathsep + os.environ.get('PATH', '')
                return True
        if tool == 'whatweb':
            try:
                subprocess.run(['wsl', 'whatweb', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
    return False

def check_dependencies():
    tools = ['nmap', 'whatweb', 'httpx']
    missing = [tool for tool in tools if not is_tool_available(tool)]
    if missing:
        print(f"\n[!] Warning: The following tools are missing or not in PATH: {', '.join(missing)}")
        print("[!] Please install them using the commands below:\n")
        
        os_type = os.name
        for tool in missing:
            cmd = INSTALL_COMMANDS.get(tool, {}).get(os_type, 'Check official docs')
            print(f"  - {tool}: {cmd}")
        print("\n")

def handler(executor):
    while True:
        check_dependencies()
        print("\n=== Reconnaissance === \n")
        print("Network Scanning:\n")
        print("[1] Quick Port Scan")
        print("[2] Full Port Scan")
        print("[3] Service Detection")
        print("[4] Operating System Detection")
        print("[5] Aggressive Scan")
        print("[6] Custom Scan\n")
        
        print("Technology Detection:\n")
        
        print("[7] Website Fingerprinting")
        print("[8] HTTP Service Discovery")
        print("[0] Back to Main Menu")


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

        safe_target = target.replace('http://', '').replace('https://', '').replace(':', '_').replace('/', '_').replace('.', '_')

        if ch == 1:
            executor.run(f"nmap -T4 {target}", outputfilename=f"nmap_quick - {safe_target}.txt")
        elif ch == 2:
            executor.run(f"nmap -p- -T4 {target}", outputfilename=f"nmap_full - {safe_target}.txt")
        elif ch == 3:
            executor.run(f"nmap -sV {target}", outputfilename=f"nmap_service - {safe_target}.txt")
        elif ch == 4:
            if not executor.run(f"sudo nmap -O {target}", outputfilename=f"nmap_os - {safe_target}.txt"):
                print("[!] Sudo execution failed. Retrying without sudo...")
                executor.run(f"nmap -O {target}", outputfilename=f"nmap_os - {safe_target}.txt")
        elif ch == 5:
            if not executor.run(f"sudo nmap -A {target}", outputfilename=f"nmap_aggressive - {safe_target}.txt"):
                print("[!] Sudo execution failed. Retrying without sudo...")
                executor.run(f"nmap -A {target}", outputfilename=f"nmap_aggressive - {safe_target}.txt")
        elif ch == 6:
            params = input("Enter Nmap parameters (e.g., -p 80,443 -sC): ").strip()
            if not executor.run(f"sudo nmap {params} {target}", outputfilename=f"nmap_custom - {safe_target}.txt"):
                print("[!] Sudo execution failed. Retrying without sudo...")
                executor.run(f"nmap {params} {target}", outputfilename=f"nmap_custom - {safe_target}.txt")
        elif ch == 7:
            cmd_prefix = "wsl " if os.name == 'nt' and not shutil.which('whatweb') else ""
            executor.run(f"{cmd_prefix}whatweb {target}", outputfilename=f"whatweb - {safe_target}.txt")
        elif ch == 8:
             executor.run(f"httpx -u {target}", outputfilename=f"httpx - {safe_target}.txt")