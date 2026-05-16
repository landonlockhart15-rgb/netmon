"""
investigation_tools.py — Auto-run security tools during device investigation.

All functions are fail-safe: exceptions are caught and returned as
evidence strings so the investigation never crashes regardless of
what tools are available.
"""

import os
import subprocess
import threading
from datetime import datetime, timezone


# ── Security Lab DB results ───────────────────────────────────────────────────

def check_existing_seclab_results(db, ip: str, max_age_hours: int = 24) -> list:
    """
    Pull recent Security Lab scan results for this IP from the DB.
    Returns a list of evidence strings ready to inject into the investigation.
    """
    try:
        from models.tables import SecurityToolRun, SecurityAIExplanation
        from sqlalchemy import desc

        cutoff_dt = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)

        runs = (
            db.query(SecurityToolRun)
            .filter(
                SecurityToolRun.target == ip,
                SecurityToolRun.status == "completed",
            )
            .order_by(desc(SecurityToolRun.id))
            .limit(10)
            .all()
        )

        results = []
        for run in runs:
            if run.completed_at:
                try:
                    ts = run.completed_at.replace(tzinfo=timezone.utc) if run.completed_at.tzinfo is None else run.completed_at
                    if ts.timestamp() < cutoff_dt:
                        continue
                    mins_ago = int((datetime.now(timezone.utc) - ts).total_seconds() / 60)
                    age_str = f" ({mins_ago}m ago)"
                except Exception:
                    age_str = ""
            else:
                age_str = ""

            ai = db.query(SecurityAIExplanation).filter(
                SecurityAIExplanation.run_id == run.id
            ).first()

            tool_name = (run.tool or "unknown").upper()
            if ai and ai.summary_text:
                results.append(
                    f"Security Lab — {tool_name} scan{age_str}: {ai.summary_text[:600]}"
                )
            elif run.raw_output_text:
                snippet = run.raw_output_text[:800].strip()
                results.append(
                    f"Security Lab — {tool_name} scan{age_str} (raw output):\n{snippet}"
                )

        return results
    except Exception as exc:
        return [f"Security Lab DB check failed: {exc}"]


# ── Detect open HTTP ports ────────────────────────────────────────────────────

def detect_http_ports(ip: str) -> list:
    """Quick check for open HTTP/HTTPS ports on a device. Returns list of open port ints."""
    import socket
    open_ports = []
    for port in [80, 443, 8080, 8443, 8888]:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


# ── Nikto ────────────────────────────────────────────────────────────────────

def run_nikto_investigation(ip: str, ports: list, timeout: int = 180) -> str:
    """
    Run a Nikto web vulnerability scan against the device.
    Requires WSL with Kali installed. Fails gracefully if unavailable.
    Returns an evidence string with key findings.
    """
    if not ports:
        return "Nikto skipped — no HTTP ports detected"

    try:
        from security.wsl import _wsl_exe

        wsl = _wsl_exe()

        # Verify Kali is available
        wsl_check = subprocess.run(
            [wsl, "--list", "--verbose"],
            capture_output=True, timeout=10,
        )
        wsl_out = wsl_check.stdout.decode("utf-16-le", errors="replace") if wsl_check.stdout else ""
        if "kali" not in wsl_out.lower():
            return "Nikto skipped — Kali WSL distro not installed"

        port = ports[0]
        use_ssl = port in (443, 8443)
        nikto_cmd = f"nikto -h {ip} -p {port} -nointeractive -maxtime 120s"
        if use_ssl:
            nikto_cmd += " -ssl"

        argv = [wsl, "-d", "kali-linux", "--",
                "script", "-q", "-c", nikto_cmd, "/dev/null"]

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        lines = []

        def _read():
            try:
                for line in iter(proc.stdout.readline, ""):
                    lines.append(line)
            finally:
                proc.stdout.close()

        t = threading.Thread(target=_read, daemon=True)
        t.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()

        t.join(timeout=5)

        meaningful = [
            l.strip() for l in lines
            if l.strip()
            and any(kw in l.lower() for kw in [
                "+ ", "osvdb", "cve-", "found", "vulnerable", "server:",
                "retrieved", "cookie", "allowed method", "interesting",
                "no cgi", "uncommon header",
            ])
        ]

        if meaningful:
            return f"Nikto web scan (port {port}):\n  " + "\n  ".join(meaningful[:25])
        return f"Nikto scan (port {port}): no significant findings"

    except FileNotFoundError:
        return "Nikto skipped — WSL not found on this system"
    except Exception as exc:
        return f"Nikto scan failed: {exc}"


# ── Shodan ────────────────────────────────────────────────────────────────────

def run_shodan_investigation(ip: str) -> str:
    """
    Query Shodan for exposure data on this device.
    For private IPs, automatically resolves the WAN IP.
    Returns an evidence string.
    """
    try:
        api_key = os.getenv("SHODAN_API_KEY", "")
        if not api_key:
            return "Shodan skipped — SHODAN_API_KEY not configured"

        from security.shodan_check import query_shodan, get_public_wan_ip
        from security.validators import is_private_ip

        lookup_ip = ip
        if is_private_ip(ip):
            wan = get_public_wan_ip(timeout=8)
            if not wan:
                return "Shodan skipped — could not determine WAN IP for private address"
            lookup_ip = wan

        data = query_shodan(lookup_ip, api_key)

        if data.get("error") == "not_found":
            return f"Shodan: {lookup_ip} not indexed (not publicly exposed or not yet scanned by Shodan)"
        if data.get("error"):
            return f"Shodan lookup failed: {data['error']}"

        parts = []
        if data.get("org"):
            parts.append(f"org: {data['org']}")
        if data.get("ports"):
            parts.append(f"exposed ports: {', '.join(str(p) for p in data['ports'][:12])}")
        if data.get("hostnames"):
            parts.append(f"hostnames: {', '.join(data['hostnames'][:5])}")
        if data.get("os"):
            parts.append(f"OS: {data['os']}")

        vulns = list((data.get("vulns") or {}).keys())
        if vulns:
            parts.append(f"KNOWN CVEs: {', '.join(vulns[:10])}")

        if parts:
            note = f" (note: Shodan looked up WAN IP {lookup_ip} — represents your router/ISP exposure)" if is_private_ip(ip) else ""
            return f"Shodan{note}: {'; '.join(parts)}"
        return f"Shodan: {lookup_ip} indexed, no notable exposure data"

    except Exception as exc:
        return f"Shodan lookup failed: {exc}"
