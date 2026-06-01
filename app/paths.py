"""
paths.py — shared filesystem path resolution.

Keeps the frozen-vs-source logic for the bundled, read-only ``static/`` assets
in one place so app.main and api.auth_routes agree (and don't import each other).
"""

import os
import sys


def static_dir() -> str:
    """
    Absolute path to the built React frontend when frozen (PyInstaller bundles
    it read-only under ``sys._MEIPASS``); the plain ``"static"`` relative path
    for source runs, where the working directory is the repo root.
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", None) or os.path.dirname(sys.executable)
        return os.path.join(base, "static")
    return "static"
