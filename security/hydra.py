import os
import re
import shutil
import subprocess
import threading

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
            # Web services: only brute-force HTTP Basic Auth. Form logins return 200
            # for everything and would produce false positives, so skip them.
            if service in ("http-get", "https-get"):
                basic = _web_auth_is_basic(target, port, service == "https-get")
                if basic is None:
                    append_output_chunk(db, run_id, stream="stdout",
                        content=f"[auto] Skipping {service}:{port} — web port not reachable for an auth probe.\n")
                    continue
                if basic is False:
                    append_output_chunk(db, run_id, stream="stdout",
                        content=(f"[auto] Skipping {service}:{port} — this is a web *form* login, not HTTP "
                                 "Basic Auth. Auto mode can't brute-force form logins without false "
                                 "positives; use the manual http-post-form option if you need to test it.\n"))
                    continue
                append_output_chunk(db, run_id, stream="stdout",
                    content=f"[auto] {service}:{port} uses HTTP Basic Auth — safe to test.\n")
            argv, svc = _build_argv(
                target=target, service=service, username=username,
                username_file_path=username_file_path, password_file_path=password_file_path,
                single_password=single_password, port=port, login_path=None,
                form_spec=None, max_parallel_tasks=max_parallel_tasks, distro=distro)
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
