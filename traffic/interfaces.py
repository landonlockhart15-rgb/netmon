"""
traffic/interfaces.py — Discover available network capture interfaces.

Uses dumpcap -D (preferred) or tshark -D to list interfaces with
human-readable names. Falls back gracefully if neither tool is present.
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


# Common Wireshark install locations on Windows
_WIRESHARK_DIRS = [
    r"C:\Program Files\Wireshark",
    r"C:\Program Files (x86)\Wireshark",
]

INSTALL_HINT = (
    "To enable packet capture:\n"
    "  1. Download Wireshark from https://www.wireshark.org/download.html\n"
    "  2. During installation, check 'Install Npcap' (required for capture)\n"
    "  3. Restart the NetMon server after installing\n"
    "  Wireshark is free and open-source."
)


def find_tool(name: str) -> Optional[str]:
    """
    Locate dumpcap.exe or tshark.exe.
    Checks PATH first, then common Wireshark install directories.
    Returns full path string or None.
    """
    found = shutil.which(name)
    if found:
        return found
    exe = f"{name}.exe"
    for d in _WIRESHARK_DIRS:
        candidate = Path(d) / exe
        if candidate.exists():
            return str(candidate)
    return None


def list_interfaces() -> Dict:
    """
    Return available capture interfaces.

    Result shape:
      {
        available:    bool,
        tool:         str | None,   # "dumpcap" | "tshark"
        interfaces:   [
          { index: int, name: str, description: str, display: str }
        ],
        error:        str | None,
        install_hint: str | None,
      }
    """
    for tool_name in ("dumpcap", "tshark"):
        path = find_tool(tool_name)
        if not path:
            continue
        try:
            r = subprocess.run(
                [path, "-D"],
                capture_output=True, text=True, timeout=10,
                creationflags=_no_window(),
            )
            output = r.stdout or r.stderr or ""
            ifaces = _parse_interface_list(output)
            if ifaces:
                return {
                    "available":    True,
                    "tool":         tool_name,
                    "interfaces":   ifaces,
                    "error":        None,
                    "install_hint": None,
                }
        except Exception:
            continue

    return {
        "available":    False,
        "tool":         None,
        "interfaces":   [],
        "error":        "Wireshark / tshark not found on this machine.",
        "install_hint": INSTALL_HINT,
    }


def _parse_interface_list(output: str) -> List[Dict]:
    """
    Parse dumpcap / tshark -D output.

    Format:  1. \\Device\\NPF_{GUID} (Friendly Name)
             2. \\Device\\NPF_{GUID2} (Wi-Fi)
    """
    ifaces = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?', line)
        if not m:
            continue
        index       = int(m.group(1))
        name        = m.group(2)
        description = m.group(3) or name
        display     = description if description != name else name
        ifaces.append({
            "index":       index,
            "name":        name,
            "description": description,
            "display":     display,
        })
    return ifaces


def _no_window() -> int:
    """Return CREATE_NO_WINDOW on Windows, 0 on other platforms."""
    try:
        import subprocess as _sp
        return _sp.CREATE_NO_WINDOW
    except AttributeError:
        return 0
