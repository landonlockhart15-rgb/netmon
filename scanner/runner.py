"""
runner.py — Executes nmap as a subprocess and returns its XML output.

Why subprocess?
  nmap is a standalone C program. Python can't import it as a library.
  subprocess.run() lets us launch it like we would from the terminal,
  capture its output, and hand it back to Python as a string.

Why XML output (-oX)?
  nmap's default output is human-readable text, which is hard to parse.
  XML output is structured — each host, port, and field has a consistent tag.
  Python's built-in xml.etree.ElementTree can then navigate it reliably.

Why -sn for the initial scan flag option?
  -sn is "ping scan" — it finds which hosts are up WITHOUT scanning ports.
  We pair it with -sV style scans when we want port info.

The flags we use:
  -sV          : probe open ports to detect the service/version running
  --open       : only show ports that are open (reduces noise)
  -oX -        : output XML to stdout (the "-" means stdout, not a file)
  --host-timeout 30s : don't wait more than 30s per host (keeps scan fast)
"""

import os
import subprocess
import shutil
from typing import Optional


def find_nmap() -> Optional[str]:
    """
    Locate the nmap executable on this system.
    Checks PATH first, then common Windows install locations as a fallback
    (the nmap installer doesn't always add itself to the system PATH).
    Returns the full path if found, None if not installed.
    """
    found = shutil.which("nmap")
    if found:
        return found
    for path in [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]:
        if os.path.isfile(path):
            return path
    return None


def run_scan(target: str, quick: bool = False) -> str:
    """
    Run an nmap scan against `target` and return the raw XML output as a string.

    Args:
        target: IP range or IP list to scan, e.g. "192.168.1.0/24" or "192.168.1.5 192.168.1.10"
        quick:  If True, run a fast ping-only scan (-sn) — finds live hosts without
                port scanning. Used for hourly device discovery. If False (default),
                run a full service-version scan (-sV) to detect open ports.

    Returns:
        Raw nmap XML output as a string.

    Raises:
        RuntimeError: if nmap is not found or the scan fails.
    """
    nmap_path = find_nmap()
    if not nmap_path:
        raise RuntimeError(
            "nmap not found. Install it from https://nmap.org/download.html "
            "and make sure it is on your PATH."
        )

    if quick:
        # Fast ping sweep — T5 aggressive timing, no DNS, 1s host timeout, 1 retry
        command = [
            nmap_path,
            "-sn",               # Ping only, no port scan
            "-T5",               # Aggressive timing (fastest)
            "-n",                # No DNS resolution
            "--host-timeout", "1s",
            "--max-retries", "1",
            "-oX", "-", target,
        ]
    else:
        # Full scan — service/version detection on open ports.
        # --top-ports 200 covers all common home-device ports (HTTP, HTTPS, SSH,
        # RTSP cameras, SMB, RDP, IoT APIs, etc.) without scanning all 1000 defaults.
        # This keeps each host scan fast enough to beat the host-timeout, whereas
        # scanning all 1000 ports with -sV always caused hosts to time out at 30s.
        command = [
            nmap_path,
            "-sV",               # Detect service versions on open ports
            "--open",            # Only report open ports
            "--top-ports", "200",  # Scan top 200 common ports (not all 1000)
            "--host-timeout", "120s",  # 4× the old limit — enough for -sV on 200 ports
            "-oX", "-",          # Output XML to stdout
            target,
        ]

    print(f"[scanner] Running: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,             # Capture both stdout and stderr
            text=True,                       # Decode bytes to str automatically
            timeout=600,                     # Kill the process if it runs > 10 minutes
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("nmap scan timed out after 5 minutes.")
    except FileNotFoundError:
        raise RuntimeError(f"nmap executable not found at: {nmap_path}")

    # nmap writes errors to stderr. If the return code is non-zero, something went wrong.
    if result.returncode != 0:
        raise RuntimeError(f"nmap exited with code {result.returncode}:\n{result.stderr}")

    # result.stdout is the raw XML string
    return result.stdout
