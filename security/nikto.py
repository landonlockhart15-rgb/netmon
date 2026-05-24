import os
import re
import shutil
import subprocess
import threading

from security.wsl import _wsl_exe
from security.common import (
    mark_run_started, append_output_chunk,
    mark_run_completed,
)
from security.ai_explain import explain_tool_output


# Ports we probe in auto mode. nmap -sV will tell us which of these are
# actually serving HTTP/HTTPS so we don't waste a nikto run on a closed port.
_AUTO_PORT_CANDIDATES = [80, 81, 280, 443, 591, 593, 832, 981,
                         1010, 1311, 2082, 2087, 2095, 2096,
                         3000, 4000, 5000, 5800, 7000, 7001, 7080,
                         8000, 8008, 8080, 8088, 8090, 8181, 8443,
                         8444, 8888, 9000, 9080, 9090, 9091, 9443,
                         10000, 16080]


def _find_nmap() -> str | None:
    for cand in ("nmap",
                 r"C:\Program Files (x86)\Nmap\nmap.exe",
                 r"C:\Program Files\Nmap\nmap.exe"):
        if shutil.which(cand) or os.path.isfile(cand):
            return cand
    return None


def _detect_http_ports(target: str) -> list[tuple[int, bool]]:
    """Return [(port, use_ssl)] of open HTTP-ish ports on target. Empty list on failure."""
    nmap = _find_nmap()
    if not nmap:
        return []
    port_arg = ",".join(str(p) for p in _AUTO_PORT_CANDIDATES)
    try:
        cflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        r = subprocess.run(
            [nmap, "-sV", "--open", "-Pn", "-T4",
             "-p", port_arg, "--host-timeout", "60s", target],
            capture_output=True, text=True, timeout=90,
            creationflags=cflags,
        )
    except Exception:
        return []
    hits: list[tuple[int, bool]] = []
    # Lines look like: "80/tcp   open  http       nginx 1.18.0"
    # or             : "443/tcp  open  ssl/http   ..."
    line_re = re.compile(r'^\s*(\d{1,5})/tcp\s+open\s+([^\s]+)', re.M)
    for m in line_re.finditer(r.stdout):
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        svc = m.group(2).lower()
        if "http" in svc or port in (80, 443, 8080, 8443, 8000, 8888):
            use_ssl = "ssl" in svc or port in (443, 8443, 9443)
            hits.append((port, use_ssl))
    # Dedup but preserve order
    seen: set[int] = set()
    out: list[tuple[int, bool]] = []
    for p, s in hits:
        if p not in seen:
            out.append((p, s)); seen.add(p)
    return out


def run_nikto(*, run_id, target, port=None, ports=None, auto=False,
              use_ssl=False, distro="kali-linux", timeout_seconds=1800):
    """
    Run nikto against one or more ports.

    auto=True       → run nmap first, scan every HTTP-ish port it finds.
    ports=[80,443]  → scan that explicit list (use_ssl auto-detected per port).
    port=80         → legacy single-port mode (preserved for old callers).
    """
    from app.database import SessionLocal
    from api.routes import _running_procs

    db = SessionLocal()
    try:
        # ── Build the list of (port, use_ssl) targets ────────────────────────
        targets: list[tuple[int, bool]] = []
        if auto:
            append_output_chunk(db, run_id, stream="stdout",
                                content=f"[nikto] auto-detecting HTTP ports on {target}...\n")
            targets = _detect_http_ports(target)
            if not targets:
                append_output_chunk(db, run_id, stream="stdout",
                                    content="[nikto] no HTTP-ish ports found, falling back to 80\n")
                targets = [(80, False)]
            else:
                summary = ", ".join(f"{p}{'/ssl' if s else ''}" for p, s in targets)
                append_output_chunk(db, run_id, stream="stdout",
                                    content=f"[nikto] detected: {summary}\n")
        elif ports:
            for p in ports:
                try: pi = int(p)
                except (TypeError, ValueError): continue
                # If caller didn't disambiguate, infer SSL for the common HTTPS ports.
                targets.append((pi, pi in (443, 8443, 9443) or use_ssl))
        else:
            targets = [(int(port) if port else 80, bool(use_ssl))]

        mark_run_started(db, run_id, command=[
            "nikto", "-h", target,
            "-ports", ",".join(str(p) for p, _ in targets),
        ])

        full_out_all = ""
        full_err_all = ""
        worst_exit = 0
        cflags = subprocess.CREATE_NO_WINDOW

        for idx, (p, ssl) in enumerate(targets, 1):
            header = (
                f"\n{'='*60}\n"
                f"[{idx}/{len(targets)}] nikto -h {target} -p {p}"
                f"{' -ssl' if ssl else ''}\n"
                f"{'='*60}\n"
            )
            append_output_chunk(db, run_id, stream="stdout", content=header)
            full_out_all += header

            # script -q creates a PTY so Perl flushes each line (no extra pkg needed)
            nikto_args = f"nikto -h {target} -nointeractive -p {p}"
            if ssl:
                nikto_args += " -ssl"
            argv = [_wsl_exe(), "-d", distro, "--",
                    "script", "-q", "-c", nikto_args, "/dev/null"]

            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                creationflags=cflags,
            )
            _running_procs[run_id] = proc

            stdout_lines: list[str] = []
            stderr_lines: list[str] = []

            def _read(pipe, store, stream):
                for line in iter(pipe.readline, ""):
                    store.append(line)
                    append_output_chunk(db, run_id, stream=stream, content=line)
                pipe.close()

            t_out = threading.Thread(target=_read, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
            t_err = threading.Thread(target=_read, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
            t_out.start(); t_err.start()

            try:
                ec = proc.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                proc.kill()
                ec = proc.wait()

            t_out.join(); t_err.join()

            full_out_all += "".join(stdout_lines)
            full_err_all += "".join(stderr_lines)
            if ec != 0:
                worst_exit = ec

        # ── Risk scoring across all ports combined ──────────────────────────
        osvdb_count = full_out_all.upper().count("OSVDB")
        if osvdb_count > 10 or "injection" in full_out_all.lower():
            risk = "critical"
        elif osvdb_count > 5:
            risk = "high"
        elif osvdb_count > 0:
            risk = "medium"
        elif full_out_all.strip():
            risk = "low"
        else:
            risk = "info"

        mark_run_completed(
            db, run_id,
            status="succeeded" if worst_exit == 0 else "failed",
            exit_code=worst_exit,
            raw_output_text=full_out_all + full_err_all,
            risk_level=risk,
        )

        threading.Thread(
            target=explain_tool_output,
            kwargs=dict(db=None, run_id=run_id, tool="nikto", target=target,
                        command=["nikto", "-h", target,
                                 "-ports", ",".join(str(p) for p, _ in targets)],
                        raw_output=full_out_all),
            daemon=True,
        ).start()

    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception:
            pass
    finally:
        _running_procs.pop(run_id, None)
        db.close()
