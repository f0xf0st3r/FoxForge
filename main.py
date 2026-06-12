import os
import sys

from core.workspace import Workspacemanager
from core.logs import Logs
from core.executor import Executor

from modules import recon

def banner():
    print("-" * 80)
    print(" FOXFORGE v1.0 ")
    print(" Unified CTF Operations Platform ")
    print("-" * 80)

def main():
    banner()
    
    # Initialize Core Components
    workspace_manager = Workspacemanager()
    logger = Logs()
    executor = Executor(logger, workspace_manager)

    print("--------------Workspace setup--------------\n")

    challenge = input("Enter Challenge Name to create/load Workspace (or press Enter to skip): ").strip()

    if challenge:
        workspace_manager.setworkspace(challenge)
    else:
        print("Running without a workspace...")

    
    while True:
        print("\n" + "="*30)
        print(" FOXFORGE MAIN MENU ")
        print("="*30)
        print("[1] Reconnaissance")
        print("[2] Web Security")
        print("[3] Cryptography")
        print("[4] Steganography")
        print("[5] Digital Forensics")
        print("[6] OSINT")
        print("[7] Reverse Engineering")
        print("[8] Binary Exploitation")
        print("[9] Utilities")
        print("[0] Exit")

        ch = input("\nSelect Category: ").strip()

        if ch == "0":
            print("\nExiting FoxForge. Goodbye!")
            sys.exit(0)
        elif ch == "1":
            recon.handler(executor)
        else:
            print("enter a valid category")

if __name__ == "__main__":
    # Ensure correct execution path
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting FoxForge.")
        sys.exit(0)