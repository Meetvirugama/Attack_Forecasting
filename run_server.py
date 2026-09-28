"""
CyberLens — Server Launcher
SIH Problem Statement #26153

Starts the Python backend API on port 8000.
In production, it also serves the React build from frontend/dist/.

Usage:
  python run_server.py           # start on default port 8000
  python run_server.py 9000      # start on custom port

The React dev server runs separately on port 5173:
  cd frontend && npm run dev
"""

import sys
import os
import webbrowser
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def open_browser(port: int, delay: float = 1.5):
    """Open browser after a short delay to let the server start."""
    time.sleep(delay)
    webbrowser.open(f'http://localhost:{port}/')

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

    # Point backend to the React production build
    dist = ROOT / 'frontend' / 'dist'
    if not dist.exists():
        print(f"[CyberLens] React build not found at {dist}")
        print("[CyberLens] Run: cd frontend && npm run build")
        print("[CyberLens] For dev mode: cd frontend && npm run dev")

    # Open browser in background thread
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    # Import and start API server
    from backend.api import start
    print(f"[CyberLens] Starting server on http://localhost:{port}/")
    print(f"[CyberLens] React app served from: frontend/dist/")
    print(f"[CyberLens] Press Ctrl+C to stop.\n")
    start(port)

if __name__ == '__main__':
    main()
