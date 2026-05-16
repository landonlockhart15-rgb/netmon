import subprocess
import threading

from security.wsl import _wsl_exe
from security.common import (
    mark_run_started, append_output_chunk,
    mark_run_completed,
)
from security.ai_explain import explain_tool_output


def run_nikto(*, run_id, target, port=None, use_ssl=False,
              distro="kali-linux", timeout_seconds=1800):
    from app.database import SessionLocal
    from api.routes import _running_procs

    db = SessionLocal()
    try:
        # script -q creates a PTY so Perl flushes each line (no extra pkg needed)
        nikto_args = f"nikto -h {target} -nointeractive"
        if port:
            nikto_args += f" -p {port}"
        if use_ssl:
            nikto_args += " -ssl"
        argv = [_wsl_exe(), "-d", distro, "--",
                "script", "-q", "-c", nikto_args, "/dev/null"]

        mark_run_started(db, run_id, command=argv)

        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        _running_procs[run_id] = proc

        stdout_lines = []
        stderr_lines = []

        def _read(pipe, store, stream):
            for line in iter(pipe.readline, ""):
                store.append(line)
                append_output_chunk(db, run_id, stream=stream, content=line)
            pipe.close()

        t_out = threading.Thread(target=_read, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=_read, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start(); t_err.start()

        try:
            exit_code = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            exit_code = proc.wait()

        t_out.join(); t_err.join()

        full_out = "".join(stdout_lines)
        full_err = "".join(stderr_lines)

        osvdb_count = full_out.upper().count("OSVDB")
        if osvdb_count > 10 or "injection" in full_out.lower():
            risk = "critical"
        elif osvdb_count > 5:
            risk = "high"
        elif osvdb_count > 0:
            risk = "medium"
        elif full_out.strip():
            risk = "low"
        else:
            risk = "info"

        # Mark run complete immediately so the UI unlocks — AI runs in background
        mark_run_completed(
            db, run_id,
            status="succeeded" if exit_code == 0 else "failed",
            exit_code=exit_code,
            raw_output_text=full_out + full_err,
            risk_level=risk,
        )

        threading.Thread(
            target=explain_tool_output,
            kwargs=dict(db=None, run_id=run_id, tool="nikto", target=target,
                        command=argv, raw_output=full_out),
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
