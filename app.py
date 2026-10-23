"""PacketStory desktop launcher (stdlib only, no install needed).

Starts the analyzer on a free local port and opens it in its own app-style window
(Edge or Chrome in --app mode). The server stops when that window is closed.
If no Chromium browser is found, the default browser is used and Ctrl+C stops the server.

Run:  python app.py        (or double-click Analyzer.bat / Analyzer.pyw)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import webbrowser
from http.server import ThreadingHTTPServer

from analyzer_backend import Handler

CANDIDATES = [
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
]


def find_browser() -> str | None:
    for c in CANDIDATES:
        p = os.path.expandvars(c)
        if os.path.isfile(p):
            return p
    return shutil.which("msedge") or shutil.which("chrome") or shutil.which("google-chrome") \
        or shutil.which("chromium")


def main() -> None:
    # Windowed/frozen builds have no console, so stdout/stderr are None and logging would crash the server.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # port 0 = any free port
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    browser = find_browser()
    try:
        if browser:
            # A private profile makes the browser run as its own process, so wait() returns on close.
            profile = tempfile.mkdtemp(prefix="packetstory-")
            try:
                subprocess.run([browser, f"--app={url}", f"--user-data-dir={profile}",
                                "--window-size=1280,860", "--no-first-run", "--no-default-browser-check",
                                "--disable-sync", "--disable-features=msImplicitSignin", "--disable-signin-promo"])
            finally:
                shutil.rmtree(profile, ignore_errors=True)
        else:
            webbrowser.open(url)
            print(f"PacketStory running at {url}  (Ctrl+C to stop)")
            threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    if getattr(sys, "frozen", False):
        os.chdir(sys._MEIPASS)  # bundled index.html lives here when built with PyInstaller
    main()
