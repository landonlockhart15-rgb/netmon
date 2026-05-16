import subprocess
import json
import os


def _router_base() -> str:
    configured = os.getenv("ROUTER_URL") or os.getenv("ROUTER_BASE")
    if configured:
        return configured.rstrip("/")
    try:
        from network.autodetect import get_network_info
        gateway = (get_network_info().get("gateway") or "").strip()
        if gateway and gateway != "unknown":
            return f"http://{gateway}"
    except Exception:
        pass
    return "http://192.168.1.1"


def _router_url(path: str) -> str:
    return _router_base() + path

NIKTO_FIX_MAP = {
    "router_security_settings": {
        "type": "router_link",
        "label": "Fix Security Headers",
        "description": "Open router Advanced Security settings",
        "path": "/adv_index.htm",
        "finding_keywords": ["x-content-type-options", "content-security-policy",
                             "strict-transport-security", "permissions-policy", "referrer-policy"],
    },
    "router_change_password": {
        "type": "router_link",
        "label": "Change Admin Password",
        "description": "Open router password change page",
        "path": "/password.htm",
        "finding_keywords": ["default account", "password 0000", "default router password"],
    },
    "router_remote_mgmt": {
        "type": "router_link",
        "label": "Disable Remote Admin",
        "description": "Open router Remote Management settings to disable it",
        "path": "/remote_mgmt.htm",
        "finding_keywords": ["remote management", "remote admin"],
    },
    "router_firmware": {
        "type": "router_link",
        "label": "Update Firmware",
        "description": "Open router firmware update page",
        "path": "/update.htm",
        "finding_keywords": ["currentsetting.htm", "userdata.json", "login.json",
                             "master.json", "conn.json", "accounts.json"],
    },
    "router_https": {
        "type": "router_link",
        "label": "Enable HTTPS",
        "description": "Open router SSL/HTTPS settings",
        "path": "/https.htm",
        "finding_keywords": ["http without ssl", "no https", "enable https"],
    },
    "info_bash_history": {
        "type": "info",
        "label": "ℹ Shell History",
        "description": "This is a false positive — Nikto checks a common path but routers don't have shell history files.",
        "info_text": "This is a Nikto false positive. Your router doesn't have a real shell history file. No action needed.",
        "finding_keywords": [".bash_history", ".sh_history"],
    },
    "info_jamonadmin": {
        "type": "info",
        "label": "ℹ JAMon Info",
        "description": "Informational only — JAMon is a Java monitor, unlikely on your home router.",
        "info_text": "Likely a false positive on a home router. If confirmed, update firmware.",
        "finding_keywords": ["jamonadmin.jsp"],
    },
}


def match_findings(raw_output: str) -> list[dict]:
    """Return list of {action_key, label, matched_line} for each matched finding."""
    lines = raw_output.splitlines()
    matched = {}
    for action_key, fix in NIKTO_FIX_MAP.items():
        if action_key in matched:
            continue
        for keyword in fix["finding_keywords"]:
            for line in lines:
                if keyword.lower() in line.lower():
                    matched[action_key] = {
                        "action_key": action_key,
                        "label": fix["label"],
                        "type": fix["type"],
                        "matched_line": line.strip(),
                    }
                    break
            if action_key in matched:
                break
    return list(matched.values())


def run_fix(action_key: str) -> dict:
    fix = NIKTO_FIX_MAP.get(action_key)
    if not fix:
        return {"ok": False, "error": f"Unknown action: {action_key}"}

    if fix["type"] == "router_link":
        return {"ok": True, "url": fix.get("url") or _router_url(fix.get("path", "/")),
                "open_in_browser": True,
                "description": fix["description"]}

    if fix["type"] == "windows_cmd":
        cmd = fix.get("cmd", [])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
            return {"ok": r.returncode == 0, "output": r.stdout or r.stderr}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if fix["type"] == "info":
        return {"ok": True, "info_text": fix.get("info_text", fix["description"])}

    return {"ok": False, "error": "Unknown fix type"}
