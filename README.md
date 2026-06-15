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

## Prerequisites

- Python 3.x
- `pyfiglet` (for the CLI banner)

Install the required dependencies using:

```bash
pip install pyfiglet
```

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
4. Select a category from the main menu to begin your operations.

## Project Structure

- `main.py` - The entry point of the application. Handles the main menu and workspace initialization.
- `core/` - Contains core operational modules such as `WorkspaceManager`, `Logs`, and `Executor`.
- `modules/` - Contains category-specific handlers (e.g., `recon.py`).
- `workspace/` - The directory where individual challenge workspaces and their data are stored.
- `logs/` - Stores execution and operation logs.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

## License

This project is open-source. Please see the LICENSE file for more information.
