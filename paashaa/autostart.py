"""Start-on-login helper (Windows registry / Linux .desktop / macOS LaunchAgent)."""
from __future__ import annotations

import os
import sys

_CMD = f'"{sys.executable}" -m paashaa'
_LINUX = os.path.expanduser("~/.config/autostart/paashaa.desktop")
_MAC = os.path.expanduser("~/Library/LaunchAgents/com.paashaa.plist")
_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


def is_enabled() -> bool:
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN) as k:
                winreg.QueryValueEx(k, "PaaShaa")
                return True
        except OSError:
            return False
    return os.path.exists(_MAC if sys.platform == "darwin" else _LINUX)


def set_enabled(on: bool) -> None:
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN, 0, winreg.KEY_SET_VALUE) as k:
            if on:
                winreg.SetValueEx(k, "PaaShaa", 0, winreg.REG_SZ, _CMD)
            else:
                try: winreg.DeleteValue(k, "PaaShaa")
                except FileNotFoundError: pass
        return
    path = _MAC if sys.platform == "darwin" else _LINUX
    if not on:
        if os.path.exists(path): os.remove(path)
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if sys.platform == "darwin":
        body = ('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.paashaa</string>'
                f'<key>ProgramArguments</key><array><string>{sys.executable}</string><string>-m</string><string>paashaa</string></array>'
                '<key>RunAtLoad</key><true/></dict></plist>')
    else:
        body = f"[Desktop Entry]\nType=Application\nName=PaaShaa\nExec={_CMD}\n"
    with open(path, "w") as f:
        f.write(body)
