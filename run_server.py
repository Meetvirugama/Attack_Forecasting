"""
AI Network Attack Forecasting — Server & Dashboard Launcher
SIH Problem Statement #26153

Launches the Python backend REST API server on port 8000 and opens
the Cyber Forensics Web Dashboard in the default browser.

Usage:
    python run_server.py            # starts on port 8000
    python run_server.py 9000       # starts on custom port
"""

import sys
import webbrowser
import threading
import time
from pathlib import Path

# Ensure project root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.api import start as run_server


def open_browser(port: int) -> None:
    """Opens the dashboard in the default browser after a short startup delay."""
    time.sleep(1.0)
    url = f"http://localhost:{port}/"
    print(f"\n[+] Opening Dashboard in browser: {url}")
    webbrowser.open(url)


def main() -> None:
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"[!] Invalid port argument '{sys.argv[1]}', using default 8000.")

    print("=" * 65)
    print("  [NIDS-ML] AI NETWORK ATTACK FORECASTING — DEFENSE CONSOLE")
    print("           SIH Problem Statement #26153 (World Models)")
    print("=" * 65)
    print(f"[*] Starting REST API Backend & Serving Frontend on port {port}...")

    # Launch browser in a separate daemon thread so it doesn't block
    browser_thread = threading.Thread(target=open_browser, args=(port,), daemon=True)
    browser_thread.start()

    # Run server (blocking call — Ctrl+C to stop)
    run_server(port)


if __name__ == "__main__":
    main()
