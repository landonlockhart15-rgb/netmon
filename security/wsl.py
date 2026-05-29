import subprocess
import shutil
import os
import re
import shlex

SECURITY_TOOLS = ["nikto", "hydra", "msfconsole", "john", "aircrack-ng", "tshark"]

def _wsl_exe():
    """Return full path to wsl.exe — FastAPI doesn't always have System32 in PATH."""
    for candidate in [
        r"C:\Windows\System32\wsl.exe",
        r"C:\Windows\SysNative\wsl.exe",
        shutil.which("wsl") or "",
    ]:
        if candidate and os.path.isfile(candidate):
            return candidate
    return "wsl"

_INSTALL_CMD = (
    "sudo apt-get update && "
    "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "
    "nikto hydra metasploit-framework john aircrack-ng tshark wireshark-common expect"
)

_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def _decode(raw: bytes) -> str:
    """Decode command output from either PowerShell/WSL UTF-16 or normal UTF-8."""
    if not raw:
        return ""
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        text = raw.decode('utf-16', errors='replace')
        return text.replace('\x00', '')
    try:
        text = raw.decode('utf-16-le', errors='strict')
        # Real UTF-16 output has many NUL bytes; UTF-8 decoded as UTF-16 looks
        # like junk. Only accept this path when it actually looks UTF-16-ish.
        if "\x00" in text or raw.count(b"\x00") > 0:
            return text.replace('\x00', '')
    except (UnicodeDecodeError, ValueError):
        pass
    try:
        return raw.decode('utf-8', errors='replace')
    except (UnicodeDecodeError, ValueError):
        return raw.decode('latin-1', errors='replace')


def _run(argv, timeout=15):
    try:
        r = subprocess.run(
            argv, capture_output=True,
            timeout=timeout, creationflags=_FLAGS,
        )
        return r.returncode, _decode(r.stdout), _decode(r.stderr)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, "", ""


def _normalize_wsl_list(text: str) -> str:
    return text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")


def _parse_wsl_distros(list_out: str) -> tuple[str | None, list[str]]:
    default_distro = None
    distros = []
    for line in _normalize_wsl_list(list_out).splitlines():
        stripped = line.strip()
        if not stripped or stripped.upper().startswith("NAME"):
            continue
        is_default = stripped.startswith("*")
        stripped = stripped.lstrip("* ").strip()
        if not stripped:
            continue
        parts = re.split(r"\s{2,}|\t+", stripped)
        name = (parts[0] if parts else stripped).strip()
        if not name:
            continue
        distros.append(name)
        if is_default:
            default_distro = name
    return default_distro, distros


def check_wsl() -> dict:
    wsl = _wsl_exe()

    # The first WSL call after a boot/login is slow because LxssManager cold-starts,
    # and the old 15s timeout could falsely report "WSL not available" even though a
    # distro is installed and healthy. Warm it with a fast, registry-only quiet list
    # first, then read verbose state with a generous timeout; if verbose still times
    # out, fall back to the quiet list so a cold-but-healthy WSL still registers.
    _run([wsl, "--list", "--quiet"], timeout=30)
    code, list_out, err = _run([wsl, "--list", "--verbose"], timeout=30)
    if code == -1:
        code, list_out, err = _run([wsl, "--list", "--quiet"], timeout=30)

    if code == -1:
        # wsl.exe not found at all
        return {
            "wsl_installed": False,
            "default_distro": None,
            "distro_list_text": "",
            "kali_present": False,
            "error": "wsl.exe was not found",
        }

    combined = _normalize_wsl_list((list_out or "") + "\n" + (err or ""))
    default_distro, distros = _parse_wsl_distros(list_out)
    lower_names = {d.lower() for d in distros}
    kali_present = any(name == "kali-linux" or name.startswith("kali") for name in lower_names)

    return {
        "wsl_installed": True,
        "default_distro": default_distro,
        "distro_list_text": _normalize_wsl_list(list_out),
        "distros": distros,
        "kali_present": kali_present,
        "error": None if code == 0 else combined.strip(),
    }


def check_tool(tool_name: str, distro: str = "kali-linux") -> dict:
    wsl = _wsl_exe()
    safe_tool = shlex.quote(tool_name)
    script = (
        f"if ! command -v {safe_tool} >/dev/null 2>&1; then echo NOT_FOUND; exit 0; fi; "
        f"command -v {safe_tool}; "
        f"timeout 8s {safe_tool} --version 2>&1 | head -n1 | "
        "tr -cd '\\11\\12\\15\\40-\\176' || true"
    )
    code, out, err = _run([wsl, "-d", distro, "--", "bash", "-lc", script], timeout=20)
    text = (out or "").strip()
    installed = code != -1 and bool(text) and "NOT_FOUND" not in text
    if not installed:
        return {"installed": False, "version": None, "error": (err or text or None)}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > 1 and not re.search(r"unknown option|unrecognized option|invalid option", lines[1], re.I):
        version = " — ".join(lines[:2])
    elif lines:
        version = f"{lines[0]} — installed"
    else:
        version = f"{tool_name} installed"
    return {"installed": True, "version": version, "error": None}


def check_all_tools(distro: str = "kali-linux") -> dict:
    return {tool: check_tool(tool, distro) for tool in SECURITY_TOOLS}


def get_install_command(distro: str = "kali-linux") -> str:
    return _INSTALL_CMD
