import json
import textwrap

from models.tables import SecurityAIExplanation
from security.common import append_output_chunk

_HEADER = (
    "You are NetMon Security Lab AI. Explain this result in plain English "
    "for a home network owner who is learning about security.\n\n"
)


# ── Per-tool prompt builders ───────────────────────────────────────────────────

def _prompt_nikto(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        Nikto scanned the web interface on {target}.
        1. Identify real vulnerabilities vs informational items.
        2. Explain what the findings mean for this device.
        3. Suggest fixes: firmware update, disable remote admin, strong password, enable HTTPS.

        Nikto output:
        {output}
    """).strip()


def _prompt_hydra(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        Hydra tested logins on {target}.
        1. Did any login succeed? Say "Credentials found: [redacted]" — do NOT show actual passwords.
        2. Is there account lockout risk?
        3. Suggest fixes: strong passwords, disable default users, disable unused SSH.

        Hydra output:
        {output}
    """).strip()


def _prompt_metasploit(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        A Metasploit module ran against {target}.
        1. What module was used and what was it testing?
        2. What evidence of vulnerability was found?
        3. How can this be fixed?

        Metasploit output:
        {output}
    """).strip()


def _prompt_john(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        John the Ripper attempted to crack password hashes.
        1. How many hashes were cracked? Do NOT show the actual passwords.
        2. What does this say about password strength?
        3. How can passwords be improved?

        John output:
        {output}
    """).strip()


def _prompt_aircrack(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        Aircrack-ng tested Wi-Fi security for {target}.
        1. Was a handshake captured? Was the password cracked? Do NOT reveal the password.
        2. What does this mean for network security?
        3. Suggest fixes: long WPA2/WPA3 passphrase, disable WPS, update router firmware.

        Aircrack-ng output:
        {output}
    """).strip()


def _prompt_shodan(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        Shodan checked internet exposure for {target} (your public IP).
        1. Explain the difference between a private LAN IP (192.168.x.x) and a public WAN IP.
        2. What ports and services are visible to the internet?
        3. Suggest fixes: disable port forwarding, disable remote admin, close UPnP, use VPN.

        Shodan output:
        {output}
    """).strip()


def _prompt_tshark(output, target):
    return textwrap.dedent(f"""
        {_HEADER}
        tshark captured and analyzed network traffic for {target}.
        1. Summarize the protocols and traffic types seen.
        2. Flag any cleartext protocols (Telnet, FTP, plain HTTP).
        3. Note any suspicious or unusual connections.

        tshark output:
        {output}
    """).strip()


def _prompt_generic(output, tool, target):
    return textwrap.dedent(f"""
        {_HEADER}
        The security tool '{tool}' ran against {target}.
        Explain what happened, what security implications it has, and what the home network owner should do next.

        Output:
        {output}
    """).strip()


def get_tool_prompt(tool: str, tool_output: str, target: str) -> str:
    builders = {
        "nikto":       _prompt_nikto,
        "hydra":       _prompt_hydra,
        "metasploit":  _prompt_metasploit,
        "john":        _prompt_john,
        "aircrack":    _prompt_aircrack,
        "aircrack-ng": _prompt_aircrack,
        "shodan":      _prompt_shodan,
        "tshark":      _prompt_tshark,
    }
    fn = builders.get(tool.lower())
    return fn(tool_output[:3000], target or "N/A") if fn else _prompt_generic(tool_output[:3000], tool, target or "N/A")


# ── Main explain function ──────────────────────────────────────────────────────

def explain_tool_output(db, *, run_id, tool, target, command, raw_output) -> dict:
    """
    Uses its own isolated DB session so that any commit error here
    does NOT poison the caller's session (which still needs to call
    mark_run_completed after us).
    """
    from app.database import SessionLocal
    fallback = {"summary": "AI explanation unavailable.", "findings": [], "recommendations": []}
    own_db = SessionLocal()

    try:
        from ai.provider import get_provider
        provider = get_provider()
        prompt   = get_tool_prompt(tool, raw_output, target or "N/A")
        result   = provider.analyze({}, prompt=prompt, kind="investigate", deep=False)
        raw      = (result.get("raw_response") or "").strip()

        summary         = raw
        findings        = []
        recommendations = []

        try:
            start = raw.find("{")
            if start != -1:
                data            = json.loads(raw[start:raw.rfind("}") + 1])
                summary         = data.get("summary", raw)
                findings        = data.get("findings", [])
                recommendations = data.get("recommendations", [])
        except (json.JSONDecodeError, ValueError):
            pass

        # Upsert — replace any prior record for this run_id (handles retries)
        existing = own_db.query(SecurityAIExplanation).filter(SecurityAIExplanation.run_id == run_id).first()
        if existing:
            existing.summary_text         = summary
            existing.findings_json        = json.dumps(findings)
            existing.recommendations_json = json.dumps(recommendations)
            existing.raw_ai_response      = raw
        else:
            own_db.add(SecurityAIExplanation(
                run_id=run_id, summary_text=summary,
                findings_json=json.dumps(findings),
                recommendations_json=json.dumps(recommendations),
                raw_ai_response=raw,
            ))
        own_db.commit()
        append_output_chunk(own_db, run_id, stream="ai", content=summary)

        return {"summary": summary, "findings": findings, "recommendations": recommendations}

    except Exception as e:
        print(f"[security.ai_explain] Error: {e}")
        try:
            own_db.rollback()
            own_db.add(SecurityAIExplanation(
                run_id               = run_id,
                summary_text         = fallback["summary"],
                findings_json        = "[]",
                recommendations_json = "[]",
            ))
            own_db.commit()
            append_output_chunk(own_db, run_id, stream="ai", content=fallback["summary"])
        except Exception:
            pass
        return fallback
    finally:
        own_db.close()
