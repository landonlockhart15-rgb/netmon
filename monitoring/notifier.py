"""
notifier.py — Push notifications and two-way command bus.

Channels:
  ntfy.sh   — Free push to Android/iOS. Works great on Pixel with the ntfy app.
              Action buttons let the user tap Block / Investigate / Dismiss without
              opening a browser.
  Email     — SMTP (Gmail app-password). Backup channel; only fires on warning+.

TWO-WAY COMMAND FLOW
  1. NetMon sends a critical alert to ntfy topic "{topic}" with action buttons.
  2. Each button is an HTTP action that POSTs to ntfy topic "{topic}-cmd".
     The POST is made by the ntfy *app on the phone*, not by ntfy's server,
     so no port-forwarding is needed — it just goes to ntfy.sh.
  3. `poll_commands()` (called every 60 s by command_poll_loop) fetches recent
     messages from "{topic}-cmd" and returns them as plain-text command strings.
  4. `execute_command(cmd)` in scheduler.py parses and executes the command.

SUPPORTED COMMANDS (sent by action buttons or typed into ntfy)
  block <ip>         — add outbound Windows Firewall block
  block-all <ip>     — add inbound+outbound block
  unblock <ip>       — remove firewall block
  investigate <ip>   — trigger AI investigation
  scan               — run immediate nmap scan
  dismiss <alert_id> — mark alert as read
"""

import base64
import json
import os
import smtplib
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.database import SessionLocal
from models.tables import Setting


# ── Settings helper ───────────────────────────────────────────────────────────

def _cfg() -> dict:
    """
    Resolve notification config. Secrets prefer environment variables over
    the DB so they're never stored in plain text on disk. Set NTFY_PASS
    and/or SMTP_PASS in .env to override the DB value.
    """
    db = SessionLocal()
    try:
        def g(k, d=""):
            row = db.query(Setting).filter(Setting.key == k).first()
            return row.value if (row and row.value is not None) else d
        ntfy_pass = os.getenv("NTFY_PASS") or g("ntfy_pass", "")
        smtp_pass = os.getenv("SMTP_PASS") or g("smtp_pass", "")
        return {
            "ntfy_enabled":  g("ntfy_enabled",  "false"),
            "ntfy_server":   g("ntfy_server",   "https://ntfy.sh"),
            "ntfy_topic":    g("ntfy_topic",    ""),
            "ntfy_user":     g("ntfy_user",     ""),
            "ntfy_pass":     ntfy_pass,
            "email_enabled": g("email_enabled", "false"),
            "email_to":      g("email_to",      ""),
            "smtp_host":     g("smtp_host",     "smtp.gmail.com"),
            "smtp_port":     g("smtp_port",     "587"),
            "smtp_user":     g("smtp_user",     ""),
            "smtp_pass":     smtp_pass,
        }
    finally:
        db.close()


def _basic_auth_header(user: str, password: str) -> str:
    """Build a Basic auth header value from user/password (latin-1 safe)."""
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {creds}"


# ── ntfy priority map ─────────────────────────────────────────────────────────

_NTFY_PRI = {
    "info":     "low",
    "warning":  "default",
    "critical": "urgent",
    "threat":   "urgent",
    "action":   "high",
}

_NTFY_TAGS = {
    "info":     "white_check_mark",
    "warning":  "warning",
    "critical": "rotating_light",
    "threat":   "skull",
    "action":   "shield",
}


# ── ntfy push ─────────────────────────────────────────────────────────────────

def send_ntfy(
    title: str,
    body: str,
    level: str = "info",
    actions: list[dict] | None = None,
    tags: list[str] | None = None,
) -> bool:
    """
    Send a push notification.

    actions: list of dicts with keys: label, url, body (optional), clear (optional bool)
    Example:
      [{"label": "Block", "url": "https://ntfy.sh/topic-cmd", "body": "block 1.2.3.4"}]
    """
    cfg = _cfg()
    if cfg["ntfy_enabled"] != "true" or not cfg["ntfy_topic"]:
        return False

    server = cfg["ntfy_server"].rstrip("/")
    topic  = cfg["ntfy_topic"]

    tag_list = [_NTFY_TAGS.get(level, "bell")] + (tags or [])

    # HTTP headers must be latin-1 — encode non-ASCII chars as XML entities
    safe_title = title.encode("ascii", errors="xmlcharrefreplace").decode("ascii")

    headers: dict[str, str] = {
        "Title":    safe_title,
        "Priority": _NTFY_PRI.get(level, "default"),
        "Tags":     ",".join(tag_list),
    }

    # Basic auth for self-hosted servers
    auth_value = ""
    if cfg["ntfy_user"] and cfg["ntfy_pass"]:
        auth_value = _basic_auth_header(cfg["ntfy_user"], cfg["ntfy_pass"])
        headers["Authorization"] = auth_value

    if actions:
        parts = []
        for a in actions:
            clear = "true" if a.get("clear", True) else "false"
            body_part = a.get("body", "")
            # Phone POSTs the action to the ntfy server itself. If that server
            # requires auth, the request must carry the same Authorization the
            # subscribe call uses — otherwise ntfy returns 401 and the ntfy app
            # surfaces it as "cannot connect".
            extra = f", headers.Authorization={auth_value}" if auth_value else ""
            parts.append(
                f'http, {a["label"]}, {a["url"]}, method=POST, '
                f'body={body_part}, clear={clear}{extra}'
            )
        headers["Actions"] = "; ".join(parts)

    try:
        req = urllib.request.Request(
            f"{server}/{topic}",
            data    = body.encode("utf-8"),
            headers = headers,
            method  = "POST",
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
        return True
    except Exception as exc:
        print(f"[notifier] ntfy error: {exc}")
        return False


def poll_commands() -> list[str]:
    """
    Check the command reply-topic ("{topic}-cmd") for messages from the last 5 min.
    Returns a list of command strings (message body text).
    """
    cfg = _cfg()
    if cfg["ntfy_enabled"] != "true" or not cfg["ntfy_topic"]:
        return []

    server    = cfg["ntfy_server"].rstrip("/")
    cmd_topic = cfg["ntfy_topic"] + "-cmd"
    url       = f"{server}/{cmd_topic}/json?poll=1&since=5m"

    try:
        req = urllib.request.Request(url, method="GET")
        if cfg["ntfy_user"] and cfg["ntfy_pass"]:
            req.add_header(
                "Authorization",
                _basic_auth_header(cfg["ntfy_user"], cfg["ntfy_pass"]),
            )
        with urllib.request.urlopen(req, timeout=10) as resp:
            commands = []
            for line in resp.read().decode("utf-8").strip().splitlines():
                try:
                    msg = json.loads(line)
                    if msg.get("event") == "message":
                        commands.append(msg.get("message", "").strip())
                except Exception:
                    pass
            return commands
    except Exception as exc:
        print(f"[notifier] command poll error: {exc}")
        return []


# ── Action button builders ────────────────────────────────────────────────────

def _cmd_url() -> str:
    cfg = _cfg()
    server = cfg["ntfy_server"].rstrip("/")
    topic  = cfg["ntfy_topic"]
    return f"{server}/{topic}-cmd"


def block_action(ip: str) -> dict:
    return {"label": f"Block {ip}", "url": _cmd_url(), "body": f"block {ip}"}


def investigate_action(ip: str) -> dict:
    return {"label": "Investigate", "url": _cmd_url(), "body": f"investigate {ip}"}


def dismiss_action() -> dict:
    return {"label": "Dismiss", "url": _cmd_url(), "body": "dismiss", "clear": True}


# ── Email ─────────────────────────────────────────────────────────────────────

def send_email(subject: str, body: str) -> bool:
    cfg = _cfg()
    if cfg["email_enabled"] != "true" or not cfg["email_to"] or not cfg["smtp_user"]:
        return False
    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"[NetMon] {subject}"
        msg["From"]    = cfg["smtp_user"]
        msg["To"]      = cfg["email_to"]
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(cfg["smtp_host"], int(cfg["smtp_port"]), timeout=15) as smtp:
            smtp.starttls()
            smtp.login(cfg["smtp_user"], cfg["smtp_pass"])
            smtp.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
        return True
    except Exception as exc:
        print(f"[notifier] email error: {exc}")
        return False


# ── Unified send ──────────────────────────────────────────────────────────────

_LEVEL_RANK = {"info": 0, "warning": 1, "action": 2, "critical": 3, "threat": 3}


def alert(
    title: str,
    body: str,
    level: str = "info",
    tags: list[str] | None = None,
    actions: list[dict] | None = None,
) -> None:
    """
    Send a notification through all enabled channels.
    ntfy only fires when level >= ntfy_min_level (default: critical).
    Email only fires for warning+.
    """
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "ntfy_min_level").first()
        min_level = row.value if (row and row.value) else "critical"
    finally:
        db.close()

    if _LEVEL_RANK.get(level, 0) >= _LEVEL_RANK.get(min_level, 3):
        send_ntfy(title, body, level=level, tags=tags, actions=actions)

    if level in ("warning", "critical", "threat", "action"):
        send_email(title, body)
