"""
Cerberus Desktop Application Launcher
Runs Cerberus as a standalone native Windows desktop application with
integrated backend server and Edge Chromium WebView2 window.
"""

import sys
import os
import socket
import threading
import time
import urllib.request
from pathlib import Path

# Ensure root directory is on path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

import uvicorn
import webview
from backend.main import app


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


def is_cerberus_running(port: int) -> bool:
    try:
        url = f"http://127.0.0.1:{port}/api/system/status"
        with urllib.request.urlopen(url, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False


def find_available_port(start_port: int = 8000) -> int:
    port = start_port
    while port < 65535:
        if is_cerberus_running(port):
            return port
        if not is_port_in_use(port):
            return port
        port += 1
    return 8000


def start_backend_server(port: int):
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()


def main():
    target_port = 8000

    # If port 8000 already has Cerberus running, connect to it
    if is_cerberus_running(target_port):
        print(f"[Cerberus Desktop] Connecting to existing Cerberus service on port {target_port}...")
    else:
        if is_port_in_use(target_port):
            target_port = find_available_port(8001)

        print(f"[Cerberus Desktop] Launching embedded backend server on port {target_port}...")
        server_thread = threading.Thread(target=start_backend_server, args=(target_port,), daemon=True)
        server_thread.start()

        # Wait for backend server to become responsive
        max_retries = 50
        ready = False
        for _ in range(max_retries):
            if is_cerberus_running(target_port):
                ready = True
                break
            time.sleep(0.1)

        if not ready:
            print("[Cerberus Desktop] Warning: Backend startup took longer than expected, opening window...")

    app_url = f"http://127.0.0.1:{target_port}"
    print(f"[Cerberus Desktop] Opening native desktop window: {app_url}")

    # Launch native Edge Chromium window
    window = webview.create_window(
        title="Cerberus — Windows-Native Behavioral Sandbox",
        url=app_url,
        width=1400,
        height=880,
        min_size=(1050, 700),
        background_color="#faf8ff",
        text_select=True,
    )

    webview.start(gui="edgechromium", debug=False)


if __name__ == "__main__":
    main()
