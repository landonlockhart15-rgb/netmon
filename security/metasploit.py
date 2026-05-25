import os
import subprocess
import tempfile
import threading

from security.wsl import _wsl_exe
from security.common import mark_run_started, append_output_chunk, mark_run_completed
from security.ai_explain import explain_tool_output


def win_to_wsl(path: str) -> str:
    if not path:
        return path
    path = path.replace("\\", "/")
    if len(path) >= 3 and path[1] == ":" and path[2] == "/":
        return f"/mnt/{path[0].lower()}{path[2:]}"
    return path


def run_metasploit(*, run_id, target, module_name, options=None,
                   distro="kali-linux", timeout_seconds=3600):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    rc_path = None
    try:
        options = options or {}
        rc_lines = [f"use {module_name}", f"set RHOSTS {target}"]
        for k, v in options.items():
            rc_lines.append(f"set {k} {v}")
        rc_lines += ["run", "exit"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False, encoding="utf-8") as f:
            f.write("\n".join(rc_lines) + "\n")
            rc_path = f.name

        argv = [_wsl_exe(), "-d", distro, "--", "msfconsole", "-q", "-r", win_to_wsl(rc_path)]
        mark_run_started(db, run_id, command=argv)

        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        _running_procs[run_id] = proc
        db_out = SessionLocal()
        db_err = SessionLocal()
        stdout_lines = []; stderr_lines = []

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

        full_out = "".join(stdout_lines); full_err = "".join(stderr_lines)
        combined = (full_out + full_err).lower()
        if "session" in combined: risk = "critical"
        elif "vulnerable" in combined: risk = "high"
        elif full_out.strip(): risk = "medium"
        else: risk = "low"

        explain_tool_output(db, run_id=run_id, tool="metasploit", target=target, command=argv, raw_output=full_out)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=full_out + full_err, risk_level=risk)
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()
        if rc_path:
            try: os.unlink(rc_path)
            except Exception: pass
