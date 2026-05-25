import os
import re
import shutil
import subprocess
import threading
from html.parser import HTMLParser
from urllib.parse import urlparse, quote

from security.wsl import _wsl_exe
from security.common import mark_run_started, append_output_chunk, mark_run_completed
from security.ai_explain import explain_tool_output

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Bundled default credential lists (ship with NetMon) — used when the caller
# supplies neither a single password nor an uploaded wordlist. On-theme for
# "is any device on my network using a weak/default password?".
_HERE = os.path.dirname(os.path.abspath(__file__))
_WORDLIST_DIR = os.path.join(_HERE, "wordlists")
_DEFAULT_PASS_LIST = os.path.join(_WORDLIST_DIR, "common-passwords.txt")
_DEFAULT_USER_LIST = os.path.join(_WORDLIST_DIR, "common-usernames.txt")

# Open-port -> hydra service module. Used by auto mode to decide what to test.
_AUTH_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet",
    139: "smb", 445: "smb", 3389: "rdp",
    80: "http-get", 8080: "http-get",
    443: "https-get", 8443: "https-get",
    3306: "mysql", 5432: "postgres",
}


def win_to_wsl(path: str) -> str:
    if not path:
        return path
    path = path.replace("\\", "/")
    if len(path) >= 3 and path[1] == ":" and path[2] == "/":
        return f"/mnt/{path[0].lower()}{path[2:]}"
    return path


def _find_nmap() -> str | None:
    for cand in ("nmap",
                 r"C:\Program Files (x86)\Nmap\nmap.exe",
                 r"C:\Program Files\Nmap\nmap.exe"):
        if shutil.which(cand) or os.path.isfile(cand):
            return cand
    return None


def _detect_auth_services(target: str, timeout: int = 90) -> list[tuple[int, str]]:
    """nmap-probe `target` for open login services. Returns [(port, hydra_service)].

    Empty list if nmap is missing or nothing relevant is open. 139 (netbios) is
    dropped when 445 is also open so SMB isn't tested twice.
    """
    nmap = _find_nmap()
    if not nmap:
        return []
    ports = sorted(_AUTH_PORT_SERVICE.keys())
    port_arg = ",".join(str(p) for p in ports)
    try:
        r = subprocess.run(
            [nmap, "--open", "-Pn", "-T4", "-p", port_arg,
             "--host-timeout", "60s", target],
            capture_output=True, text=True, timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return []
    found: list[tuple[int, str]] = []
    open_ports: set[int] = set()
    for m in re.finditer(r'^\s*(\d{1,5})/tcp\s+open\b', r.stdout, re.M):
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        if port in _AUTH_PORT_SERVICE:
            open_ports.add(port)
    for port in sorted(open_ports):
        if port == 139 and 445 in open_ports:
            continue  # SMB already covered by 445
        found.append((port, _AUTH_PORT_SERVICE[port]))
    return found


def _web_auth_is_basic(target: str, port: int, use_ssl: bool, timeout: int = 8) -> bool | None:
    """Probe a web port to decide if hydra's http-get can test it reliably.

    Returns True if the endpoint uses HTTP Basic Auth (401 + 'WWW-Authenticate: Basic'),
    in which case http-get is accurate. Returns False for form-based/open pages
    (where http-get would report false positives), and None if unreachable.
    """
    import urllib.request
    import urllib.error
    import ssl

    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{target}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="GET"),
                               timeout=timeout, context=ctx)
        return False  # answered without an auth challenge -> not Basic Auth
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "basic" in (e.headers.get("WWW-Authenticate", "") or "").lower()
        return False
    except Exception:
        return None


# ── Web form-login auto-testing (http-post-form) ───────────────────────────────
# For form logins (not Basic Auth) we fetch the page, detect the form fields,
# submit a deliberately-wrong credential to learn the failure response, then
# build a hydra http-post-form spec. This lets auto mode test web logins
# accurately instead of skipping them — and skip safely when it can't.

def _hydra_escape(s: str) -> str:
    # ':' separates fields in hydra's post-form spec, so literal ':' must be escaped.
    return (s or "").replace("\\", "\\\\").replace(":", r"\:")


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "inputs": []}
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({
                "type": (a.get("type") or "text").lower(),
                "name": a.get("name", ""),
                "value": a.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _fetch(target, port, use_ssl, path="/", method="GET", data=None, timeout=8):
    import urllib.request
    import urllib.error
    import ssl
    scheme = "https" if use_ssl else "http"
    if not path.startswith("/"):
        path = "/" + path
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": "NetMon-SecurityLab"}
    body = data.encode() if isinstance(data, str) else data
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(f"{scheme}://{target}:{port}{path}", data=body,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(200_000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def _detect_login_form(target, port, use_ssl) -> dict | None:
    _status, body = _fetch(target, port, use_ssl, "/")
    if not body:
        return None
    parser = _FormParser()
    try:
        parser.feed(body)
    except Exception:
        pass
    for form in parser.forms:
        pw = next((i for i in form["inputs"] if i["type"] == "password" and i["name"]), None)
        if not pw:
            continue
        text_inputs = [i for i in form["inputs"] if i["type"] in ("text", "email") and i["name"]]
        user_field = None
        for i in text_inputs:
            if re.search(r"user|login|email|name|account|admin", i["name"], re.I):
                user_field = i["name"]
                break
        if not user_field and text_inputs:
            user_field = text_inputs[0]["name"]
        extra: dict[str, str] = {}
        csrf = False
        for i in form["inputs"]:
            n = i["name"]
            if not n or n == user_field or n == pw["name"]:
                continue
            if i["type"] in ("submit", "button", "image", "reset"):
                continue
            if re.search(r"csrf|token|nonce|authenticity|_wpnonce", n, re.I):
                csrf = True
            extra[n] = i["value"]
        action = form["action"].strip()
        if not action:
            path = "/"
        else:
            parsed = urlparse(action)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        return {"path": path, "user_field": user_field, "pass_field": pw["name"],
                "extra": extra, "csrf": csrf}
    return None


def _failure_marker(body: str, pass_field: str) -> str | None:
    low = body.lower()
    for phrase in ("incorrect", "invalid", "failed", "denied", "not match", "try again",
                   "unauthorized", "wrong", "bad credentials", "authentication failed", "error"):
        if phrase in low:
            return phrase
    # Fallback: a failed login usually re-renders the form (password field still present).
    if pass_field and re.search(rf'name=["\']?{re.escape(pass_field)}["\']?', body, re.I):
        return f'name="{pass_field}"'
    return None


def _build_web_form_test(target, port, use_ssl) -> tuple[str | None, str]:
    """Returns (hydra http-post-form spec, human note). spec is None when the form
    can't be auto-tested reliably."""
    form = _detect_login_form(target, port, use_ssl)
    if not form:
        return None, (f"[auto] Skipping web login on {port}: no HTML login form with a password "
                      "field found (it may be JavaScript-rendered).")
    if form["csrf"]:
        return None, (f"[auto] Skipping web login on {port}: the form uses a CSRF token that changes "
                      "each request — hydra can't replay it, so it can't be auto-tested safely.")
    if not form["user_field"] or not form["pass_field"]:
        return None, f"[auto] Skipping web login on {port}: couldn't identify the username/password fields."

    spec_parts, real_parts = [], []
    for name, val in form["extra"].items():
        spec_parts.append(f"{name}={_hydra_escape(val)}")
        real_parts.append(f"{quote(name, safe='')}={quote(val, safe='')}")
    spec_parts.append(f"{form['user_field']}=^USER^")
    spec_parts.append(f"{form['pass_field']}=^PASS^")
    real_parts.append(f"{quote(form['user_field'], safe='')}=nmprobe_x")
    real_parts.append(f"{quote(form['pass_field'], safe='')}=nmprobe_wrong_zzz")

    _status, body = _fetch(target, port, use_ssl, form["path"], "POST", "&".join(real_parts))
    marker = _failure_marker(body, form["pass_field"]) if body else None
    if not marker:
        return None, (f"[auto] Skipping web login on {port}: couldn't determine a reliable failure "
                      "response from a bad-credential probe, so testing would risk false positives.")
    spec = f"{form['path']}:{'&'.join(spec_parts)}:F={_hydra_escape(marker)}"
    return spec, (f"[auto] Login form detected on {port} (fields {form['user_field']}/"
                  f"{form['pass_field']}, failure marker '{marker[:30]}') — testing it as a form login.")


def _resolve_creds(db, username, username_file_path, password_file_path, single_password):
    """Apply default-credential fallbacks. Returns (username, username_file_path,
    password_file_path, single_password). Caller-supplied values always win."""
    # Password source: explicit single password > uploaded wordlist > bundled list.
    if not password_file_path and not single_password:
        try:
            from models.tables import SecurityFile
            pf = db.query(SecurityFile).filter(SecurityFile.file_type == "wordlist").first()
            if pf:
                password_file_path = pf.storage_path
        except Exception:
            pass
        if not password_file_path and os.path.isfile(_DEFAULT_PASS_LIST):
            password_file_path = _DEFAULT_PASS_LIST
    # Username source: explicit user/list > bundled common-usernames list.
    if not username and not username_file_path and os.path.isfile(_DEFAULT_USER_LIST):
        username_file_path = _DEFAULT_USER_LIST
    return username, username_file_path, password_file_path, single_password


def _build_argv(*, target, service, username, username_file_path, password_file_path,
                single_password, port, login_path, form_spec, max_parallel_tasks, distro):
    if service == "http":
        service = "http-get"
    elif service == "https":
        service = "https-get"

    argv = [_wsl_exe(), "-d", distro, "--", "hydra", "-t", str(max_parallel_tasks)]
    if username:
        argv += ["-l", username]
    elif username_file_path:
        argv += ["-L", win_to_wsl(username_file_path)]
    if password_file_path:
        argv += ["-P", win_to_wsl(password_file_path)]
    elif single_password:
        argv += ["-p", single_password]
    if port:
        argv += ["-s", str(port)]
    argv.append(target)
    argv.append(service)
    if service in ("http-get", "https-get", "http-post-form", "https-post-form"):
        # These modules require a path/form argument; default to the web root.
        argv.append(form_spec or login_path or "/")
    return argv, service


def _found_creds(combined: str) -> bool:
    """True if hydra actually recovered credentials. Different modules report this
    differently: ssh/ftp print '[SUCCESS]', http-get prints
    '[443][http-get] host: ... login: ... password: ...' and 'N valid passwords found'."""
    m = re.search(r'(\d+)\s+valid password', combined, re.I)
    if m:
        return int(m.group(1)) > 0
    if "[SUCCESS]" in combined:
        return True
    return bool(re.search(r'^\[\d+\]\[[^\]]+\].*\bpassword:\s*\S', combined, re.M))


def _risk(combined: str) -> str:
    return "critical" if _found_creds(combined) else "low"


def _stream_proc(argv, run_id, timeout_seconds=1800) -> tuple[int, str]:
    """Run one process, stream stdout/stderr into run_id, return (exit_code, combined)."""
    from app.database import SessionLocal
    from api.routes import _running_procs
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, creationflags=_CREATE_NO_WINDOW)
    _running_procs[run_id] = proc
    db_out = SessionLocal()
    db_err = SessionLocal()
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    def _read(pipe, thread_db, store, stream):
        try:
            for line in iter(pipe.readline, ""):
                store.append(line)
                append_output_chunk(thread_db, run_id, stream=stream, content=line)
        finally:
            pipe.close()
            thread_db.close()

    t_out = threading.Thread(target=_read, args=(proc.stdout, db_out, stdout_lines, "stdout"), daemon=True)
    t_err = threading.Thread(target=_read, args=(proc.stderr, db_err, stderr_lines, "stderr"), daemon=True)
    t_out.start(); t_err.start()
    try:
        exit_code = proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill(); exit_code = proc.wait()
    t_out.join(); t_err.join()
    return exit_code, "".join(stdout_lines) + "".join(stderr_lines)


def run_hydra(*, run_id, target, service, username=None, username_file_path=None,
              password_file_path=None, single_password=None, port=None,
              login_path=None, form_spec=None, max_parallel_tasks=4,
              distro="kali-linux", timeout_seconds=1800):
    """Single-service hydra run (manual mode)."""
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        username, username_file_path, password_file_path, single_password = _resolve_creds(
            db, username, username_file_path, password_file_path, single_password)
        argv, service = _build_argv(
            target=target, service=service, username=username,
            username_file_path=username_file_path, password_file_path=password_file_path,
            single_password=single_password, port=port, login_path=login_path,
            form_spec=form_spec, max_parallel_tasks=max_parallel_tasks, distro=distro)

        mark_run_started(db, run_id, command=argv)
        exit_code, combined = _stream_proc(argv, run_id, timeout_seconds)
        explain_tool_output(db, run_id=run_id, tool="hydra", target=target, command=argv, raw_output=combined)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=combined, risk_level=_risk(combined))
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception:
            pass
    finally:
        _running_procs.pop(run_id, None); db.close()


def run_hydra_auto(*, run_id, target, username=None, username_file_path=None,
                   password_file_path=None, single_password=None,
                   max_parallel_tasks=4, distro="kali-linux", per_service_timeout=900):
    """Auto mode: nmap-detect open login services on `target`, then run hydra
    against each one in turn. The user only has to provide the target."""
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        mark_run_started(db, run_id, command=["hydra-auto", target])
        append_output_chunk(db, run_id, stream="stdout",
                            content=f"[auto] Scanning {target} for open login services…\n")

        services = _detect_auth_services(target)
        if not services:
            if not _find_nmap():
                msg = ("[auto] nmap not found — cannot auto-detect services. Install nmap "
                       "(https://nmap.org/download.html) or pick a service manually.\n")
                append_output_chunk(db, run_id, stream="stderr", content=msg)
                mark_run_completed(db, run_id, status="failed", raw_output_text=msg, risk_level="low")
            else:
                msg = ("[auto] No open login services found on this target "
                       "(checked ssh, ftp, telnet, rdp, smb, http, https, mysql, postgres).\n")
                append_output_chunk(db, run_id, stream="stdout", content=msg)
                mark_run_completed(db, run_id, status="succeeded", exit_code=0,
                                   raw_output_text=msg, risk_level="low")
            return

        listing = ", ".join(f"{svc}:{port}" for port, svc in services)
        append_output_chunk(db, run_id, stream="stdout",
                            content=f"[auto] Open login services: {listing}\n")

        username, username_file_path, password_file_path, single_password = _resolve_creds(
            db, username, username_file_path, password_file_path, single_password)

        all_output: list[str] = []
        any_success = False
        for port, service in services:
            append_output_chunk(db, run_id, stream="stdout",
                                content=f"\n=== Testing {service} on port {port} ===\n")
            run_service = service
            form_spec = None
            # Web services: HTTP Basic Auth -> http-get (reliable). Form login -> auto-build
            # an http-post-form test (detect fields + failure marker), or skip with a reason.
            if service in ("http-get", "https-get"):
                use_ssl = service == "https-get"
                basic = _web_auth_is_basic(target, port, use_ssl)
                if basic is None:
                    append_output_chunk(db, run_id, stream="stdout",
                        content=f"[auto] Skipping {service}:{port} — web port not reachable for an auth probe.\n")
                    continue
                if basic is False:
                    spec, note = _build_web_form_test(target, port, use_ssl)
                    append_output_chunk(db, run_id, stream="stdout", content=note + "\n")
                    if not spec:
                        continue
                    run_service = "https-post-form" if use_ssl else "http-post-form"
                    form_spec = spec
                else:
                    append_output_chunk(db, run_id, stream="stdout",
                        content=f"[auto] {service}:{port} uses HTTP Basic Auth — safe to test.\n")
            argv, svc = _build_argv(
                target=target, service=run_service, username=username,
                username_file_path=username_file_path, password_file_path=password_file_path,
                single_password=single_password, port=port, login_path=None,
                form_spec=form_spec, max_parallel_tasks=max_parallel_tasks, distro=distro)
            try:
                _exit, combined = _stream_proc(argv, run_id, per_service_timeout)
            except Exception as e:
                append_output_chunk(db, run_id, stream="stderr", content=f"[auto] {service} failed: {e}\n")
                continue
            all_output.append(f"### {service}:{port}\n{combined}")
            if _found_creds(combined):
                any_success = True

        full = "\n\n".join(all_output)
        append_output_chunk(db, run_id, stream="stdout",
                            content=("\n[auto] Done. " + ("Weak/default credentials FOUND — see above.\n"
                                     if any_success else "No weak credentials found on the tested services.\n")))
        explain_tool_output(db, run_id=run_id, tool="hydra", target=target,
                            command=["hydra-auto", target], raw_output=full)
        mark_run_completed(db, run_id, status="succeeded", exit_code=0,
                           raw_output_text=full, risk_level="critical" if any_success else "low")
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception:
            pass
    finally:
        _running_procs.pop(run_id, None); db.close()
