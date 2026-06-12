def handler(executor):
    while True:
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


        ch = int(input("Select from the available options : "))

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
            executor.run(f"sudo nmap -O {target}", outputfilename=f"nmap_os - {safe_target}.txt")
        elif ch == 5:
            executor.run(f"sudo nmap -A {target}", outputfilename=f"nmap_aggressive - {safe_target}.txt")
        elif ch == 6:
            params = input("Enter Nmap parameters (e.g., -p 80,443 -sC): ").strip()
            executor.run(f"sudo nmap {params} {target}", outputfilename=f"nmap_custom - {safe_target}.txt")
        elif ch == 7:
            executor.run(f"whatweb {target}", outputfilename=f"whatweb - {safe_target}.txt")
        elif ch == 8:
             executor.run(f"httpx -u {target}", outputfilename=f"httpx - {safe_target}.txt")