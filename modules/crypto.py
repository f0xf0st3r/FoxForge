import os
import shutil
import subprocess

def check_dependencies():
    """Warn the user about missing external tools used in cryptography and offer to install."""
    tools = {
        'hashid': 'pip install hashid',
        'xortool': 'pip install xortool',
    }
    missing = [tool for tool in tools if not shutil.which(tool)]
    
    if missing:
        print(f"\n[!] Warning: The following tools are missing or not in PATH: {', '.join(missing)}")
        for tool in missing:
            print(f"  - {tool}: Requires '{tools[tool]}'")
        install = input("    > Would you like to install them now? (y/n): ").strip().lower()
        if install == 'y':
            for tool in missing:
                print(f"    [*] Installing {tool}...")
                subprocess.run(tools[tool], shell=True)
            print("    [+] Done. Please restart if tools still aren't found.\n")

def UserInputOptions():
    print(" [1] Enter your text : ")
    print(" [2] Enter your .txt file path : ")
    
    try:
        ch = int(input("Select from the available options : "))
    except ValueError:
        print("Invalid input! Please enter a valid option.")
        return None

    if ch == 1:
        text = input("Enter your text ")
        if not text:
            print("Input cannot be empty!!!")
            return None
        return text
    
    elif ch == 2:
        path = input("  Enter file path ").strip().strip('"').strip("'")
        if not os.path.isfile(path):
            print("No file found..")
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                print("File has no content inside it...")
                return None
            return content
        except Exception as e:
            print(f"  [!] Error reading file: {e}")
            return None
    else:
        print("Invalid choice.")
        return None


def handle(executor):
    check_dependencies()
    while True:
        print("\n=== Cryptography ===")
        print("[1] Identify Hash Type")
        print("[2] Decode Base64")
        print("[3] Encode Base64")
        print("[4] Generate Hash")
        print("[5] Analyze Cipher")
        print("[0] Back to Main Menu")

        choice = input("\nSelect from the available options: ").strip()

        if choice == "0":
            break

        if choice == "1":
            data = UserInputOptions()
            if not data:
                continue
            executor.run(
                f'hashid "{data}"',
                outputdir="extracted",
                outputfilename="hashid.txt",
            )

        elif choice == "2":
            data = UserInputOptions()
            if not data:
                continue
            
            import base64
            print('executing base64 decode')
            try:
                # Auto-fix missing padding
                padded_data = data + '=' * (-len(data) % 4)
                decoded_bytes = base64.b64decode(padded_data)
                
                if executor.workspace.currentworkspace:
                    out_dir = executor.workspace.getdirpath("extracted")
                    os.makedirs(out_dir, exist_ok=True)
                    out_path = os.path.join(out_dir, "b64_decode.txt")
                    
                    with open(out_path, "wb") as f:
                        f.write(decoded_bytes)
                    
                    # Safe text preview for the terminal
                    preview = decoded_bytes.decode('utf-8', errors='replace')
                    print(preview)
                    print(f"output saved to b64_decode.txt")
                    
                    executor.logs.logexe("base64 decode", "SUCCESS", out_path, executor.workspace.getdirpath("logs"))
                else:
                    print("  [!] No workspace active, output not saved.")
            except Exception as e:
                print(f"  [!] Invalid Base64 Data: {e}")

        elif choice == "3":
            data = UserInputOptions()
            if not data:
                continue

            import base64
            print('executing base64 encode')
            try:
                encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
                
                if executor.workspace.currentworkspace:
                    out_dir = executor.workspace.getdirpath("extracted")
                    os.makedirs(out_dir, exist_ok=True)
                    out_path = os.path.join(out_dir, "b64_encode.txt")
                    
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write(encoded + "\n")
                    
                    print(encoded)
                    print(f"output saved to b64_encode.txt")
                    
                    executor.logs.logexe("base64 encode", "SUCCESS", out_path, executor.workspace.getdirpath("logs"))
                else:
                    print("  [!] No workspace active, output not saved.")
            except Exception as e:
                print(f"  [!] Error encoding: {e}")

        elif choice == "4":
            data = UserInputOptions()
            if not data:
                continue

            print("[1] MD5")
            print("[2] SHA-1")
            print("[3] SHA-256")
            print("[4] SHA-512")
            print("[0] Back to Main Menu")

            algo_choice = input("Select from the available options: ").strip()

            if algo_choice == "0":
                break

            algo_map = {"1": "md5", "2": "sha1", "3": "sha256", "4": "sha512"}
            if algo_choice in algo_map:
                algo = algo_map[algo_choice]
                hex_data = data.encode('utf-8').hex()
                executor.run(
                    f'python -c "import sys, hashlib; sys.stdout.write(hashlib.{algo}(bytes.fromhex(sys.argv[1])).hexdigest() + \'\\n\')" {hex_data}',
                    outputdir="extracted",
                    outputfilename=f"{algo}.txt",
                )
            else:
                print("Invalid choice.")

        elif choice == "5":
            print("\n=== Analyze Cipher ===")
            print("[1] Caesar Brute Force")
            print("[2] ROT13 Analysis")
            print("[3] Frequency Analysis")
            print("[4] XOR Analysis (xortool)")
            print("[5] Auto Cipher Detection")
            print("[0] Back")
            
            method = input("\nSelect method: ").strip()

            if method == "0":
                continue

            data = UserInputOptions()
            if not data:
                continue

            # --- 1. Caesar Brute Force ---
            elif method == "1":
                script = """
import sys
data = bytes.fromhex(sys.argv[1]).decode('utf-8')
print(f"Input: {data}\\n")
for shift in range(1, 26):
    result = ""
    for c in data:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    print(f"Shift {shift:2d} : {result}")
"""
                import base64
                b64_script = base64.b64encode(script.encode('utf-8')).decode('utf-8')
                hex_data = data.encode('utf-8').hex()
                
                executor.run(
                    f'python -c "import sys, base64; exec(base64.b64decode(\'{b64_script}\').decode(\'utf-8\'))" {hex_data}',
                    outputdir="extracted",
                    outputfilename="caesar_bruteforce.txt",
                )

            # --- 2. ROT13 Analysis ---
            elif method == "2":
                hex_data = data.encode('utf-8').hex()
                executor.run(
                    f'python -c "import sys, codecs; sys.stdout.write(\'Input : \' + bytes.fromhex(sys.argv[1]).decode(\'utf-8\') + \'\\nROT13 : \' + codecs.encode(bytes.fromhex(sys.argv[1]).decode(\'utf-8\'), \'rot_13\') + \'\\n\')" {hex_data}',
                    outputdir="extracted",
                    outputfilename="rot13_output.txt",
                )

            # --- 3. Frequency Analysis ---
            elif method == "3":
                script = """
import sys
from collections import Counter
data = bytes.fromhex(sys.argv[1]).decode('utf-8')
letters = [c.lower() for c in data if c.isalpha()]
total = len(letters)

if total == 0:
    print("No alphabetic characters found.")
    sys.exit(0)

freq = Counter(letters)
max_count = freq.most_common(1)[0][1]
bar_width = 20

print(f"  Input: {data}")
print(f"  Total letters: {total}\\n")
print(f"  +------+-------+--------+----------------------+")
print(f"  | Char | Count | Freq % | Distribution         |")
print(f"  +------+-------+--------+----------------------+")
for char, count in freq.most_common():
    pct = (count / total) * 100
    bar_len = int((count / max_count) * bar_width)
    bar = "#" * bar_len
    print(f"  | {char:^4} | {count:^5} | {pct:>5.1f}% | {bar:<{bar_width}} |")
print(f"  +------+-------+--------+----------------------+")

english_freq = "etaoinshrdlcumwfgypbvkjxqz"
sorted_by = ''.join([ch for ch, _ in freq.most_common()])
print(f"\\n  --- Letter Frequency Comparison ---")
print(f"  Cipher text : {sorted_by}")
print(f"  English ref : {english_freq[:len(sorted_by)]}")
print(f"\\n  Hint: Map most frequent cipher letter to 'e', second to 't', etc.")
"""
                import base64
                b64_script = base64.b64encode(script.encode('utf-8')).decode('utf-8')
                hex_data = data.encode('utf-8').hex()
                
                executor.run(
                    f'python -c "import sys, base64; exec(base64.b64decode(\'{b64_script}\').decode(\'utf-8\'))" {hex_data}',
                    outputdir="extracted",
                    outputfilename="frequency_analysis.txt",
                )

            # --- 4. XOR Analysis (xortool) ---
            elif method == "4":
                print("\n  [1] Auto detection (xortool)  [2] Known key (xortool-xor)")
                xor_choice = input("  Select: ").strip()
                
                if xor_choice in ["1", "2"]:
                    if not executor.workspace.currentworkspace:
                        print("  [!] No workspace active.")
                        continue
                        
                    out_dir = executor.workspace.getdirpath("extracted")
                    os.makedirs(out_dir, exist_ok=True)
                    tmp_path = os.path.join(out_dir, "xor_input.bin")
                    
                    with open(tmp_path, "wb") as f:
                        f.write(data.encode('utf-8'))
                        
                    if xor_choice == "1":
                        print("\n  Most probable plaintext character:")
                        print("  [1] Space (0x20) - English text (default)")
                        print("  [2] Null (0x00) - Binary data")
                        print("  [3] Custom hex value")
                        char_choice = input("  Select [1]: ").strip() or "1"
                        
                        if char_choice == "2":
                            prob_char = "00"
                        elif char_choice == "3":
                            prob_char = input("  Enter hex value (e.g. 20): ").strip()
                        else:
                            prob_char = "20"
                        
                        executor.run(f'xortool -c {prob_char} "{tmp_path}"', outputdir="extracted", outputfilename="xortool_output.txt")
                    else:
                        key = input("  Enter XOR key (hex, e.g. 1a2b): ").strip()
                        if key:
                            executor.run(f'xortool-xor -h "{key}" -f "{tmp_path}"', outputdir="extracted", outputfilename="xor_decrypted.txt")
                else:
                    print("  [!] Invalid choice.")

            # --- 5. Automatic Cipher Detection ---
            elif method == "5":
                script = """
import sys, re, codecs, base64
data = bytes.fromhex(sys.argv[1]).decode('utf-8')

# Expanded word list for better detection
common = [
    'the','and','is','in','to','of','it','for','on','are','was','that','with','this',
    'have','from','or','an','be','as','at','by','not','but','we','can','all','her',
    'his','one','our','out','you','had','has','its','let','may','new','now','old',
    'see','way','who','did','get','how','man','day','been','call','come','each',
    'make','like','long','look','many','most','over','such','take','than','them',
    'very','when','what','will','your','just','know','time','very','about','could',
    'hello','world','flag','password','secret','key','test','text','code','data'
]

def score(text):
    t = ' ' + text.lower() + ' '
    return sum(1 for w in common if ' ' + w + ' ' in t or t.startswith(w + ' ') or t.endswith(' ' + w))

def is_readable(text):
    if len(text) == 0:
        return False
    printable = sum(1 for c in text if c.isalpha() or c == ' ')
    return (printable / len(text)) > 0.7

print(f"Input: {data}")
print("\\n--- Detection Results ---\\n")
found = False

# Check Base64
b64_pat = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
if len(data) >= 4 and len(data) % 4 == 0 and b64_pat.match(data):
    try:
        decoded = base64.b64decode(data).decode('utf-8', errors='replace')
        if score(decoded) >= 1 or is_readable(decoded):
            print(f"[+] Base64 detected")
            print(f"    Decoded: {decoded}")
            found = True
    except Exception:
        pass

# Check Hex
hex_pat = re.compile(r'^[0-9a-fA-F]+$')
if len(data) >= 2 and len(data) % 2 == 0 and hex_pat.match(data):
    try:
        decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
        if score(decoded) >= 1 or is_readable(decoded):
            print(f"[+] Hex encoding detected")
            print(f"    Decoded: {decoded}")
            found = True
    except Exception:
        pass

# Check ROT13
rot13 = codecs.encode(data, 'rot_13')
if score(rot13) >= 1 or (is_readable(rot13) and not is_readable(data)):
    print(f"[+] ROT13 detected")
    print(f"    Decoded: {rot13}")
    found = True

# Check Caesar (all shifts)
best_shift, best_score, best_text = 0, 0, ""
for shift in range(1, 26):
    result = ""
    for c in data:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    s = score(result)
    if s > best_score:
        best_shift, best_score, best_text = shift, s, result
if best_score >= 1:
    print(f"[+] Caesar cipher detected (shift {best_shift})")
    print(f"    Decoded: {best_text}")
    found = True

if not found:
    print("[-] No known cipher pattern detected.")
"""
                import base64
                b64_script = base64.b64encode(script.encode('utf-8')).decode('utf-8')
                hex_data = data.encode('utf-8').hex()
                
                executor.run(
                    f'python -c "import sys, base64; exec(base64.b64decode(\'{b64_script}\').decode(\'utf-8\'))" {hex_data}',
                    outputdir="extracted",
                    outputfilename="cipher_detection.txt",
                )

            else:
                print("  [!] Invalid method.")

        else:
            print("Invalid choice.")