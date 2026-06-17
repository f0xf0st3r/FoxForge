# FoxForge

**FoxForge** is a Unified CTF (Capture The Flag) Operations Platform. It provides a centralized command-line interface to organize your CTF challenges, manage workspaces, keep logs, and execute tools across various cybersecurity domains.

## Features

- **Workspace Management:** Automatically set up and manage workspaces for individual CTF challenges, keeping your files and progress organized.
- **Logging Engine:** Built-in logging system to keep track of your commands, findings, and operations.
- **Categorized Tool Execution:** Run operations specific to various CTF categories:
  - Reconnaissance
  - Web Security
  - Cryptography
  - Steganography
  - Digital Forensics
  - OSINT
  - Reverse Engineering
  - Binary Exploitation
  - Utilities

## Prerequisites & Installation

- **Python 3.x**
- **External Tools:** FoxForge relies heavily on system-level command-line tools.

### 1. Install System Dependencies (Linux/Kali)

To ensure all modules work flawlessly, you must install the required standalone tools. Run the following one-liner on a Kali/Debian based system:

```bash
sudo apt update && sudo apt install -y checksec ropgadget ffuf nuclei wordlists dirb nmap whatweb httpx-toolkit libimage-exiftool-perl steghide binwalk stegseek zsteg file binutils upx-ucl radare2 foremost bulk-extractor volatility3 hashid coreutils openssl sherlock theharvester xxd jq zbar-tools qrencode
```
*(Note: On Kali Linux, wordlists are pre-installed but may need unzipping via `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`)*

### 2. Install Python Dependencies

Install the required Python packages (including `pyfiglet`, `pwntools`, and `sqlmap`) using the provided requirements file:

```bash
pip install -r requirements.txt
```

*(For a detailed breakdown of which tools each module requires, please refer to the `requirements.txt` file.)*

## Usage

1. Clone the repository and navigate to the root directory:
   ```bash
   git clone https://github.com/f0xf0st3r/FoxForge.git
   cd FoxForge
   ```

2. Run the platform:
   ```bash
   python main.py
   ```

3. Enter a challenge name to create or load a workspace, or press Enter to run without one.
4. Select a category from the main menu to begin your operations and follow the on-screen prompts.

## Project Structure

- `main.py` - The entry point of the application. Handles the main menu and workspace initialization.
- `core/` - Contains core operational modules such as `WorkspaceManager`, `Logs`, and `Executor`.
- `modules/` - Contains category-specific handlers (e.g., `recon.py`).
- `workspaces/` - The directory where individual challenge workspaces and their data are stored. (Outputs are categorized into `reports`, `extracted`, and `logs`).
- `logs/` - Stores global execution and operation logs.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License

This project is open-source. Please see the LICENSE file for more information.
