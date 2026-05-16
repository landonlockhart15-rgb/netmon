import subprocess
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


def run_hydra(*, run_id, target, service, username=None, username_file_path=None,
              password_file_path=None, single_password=None, port=None,
              login_path=None, form_spec=None, max_parallel_tasks=4,
              distro="kali-linux", timeout_seconds=1800):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
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
            if form_spec:
                argv.append(form_spec)
            elif login_path:
                argv.append(login_path)

        mark_run_started(db, run_id, command=argv)
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        _running_procs[run_id] = proc
        stdout_lines = []; stderr_lines = []

        def _read(pipe, store, stream):
            for line in iter(pipe.readline, ""):
                store.append(line); append_output_chunk(db, run_id, stream=stream, content=line)
            pipe.close()

        t_out = threading.Thread(target=_read, args=(proc.stdout, stdout_lines, "stdout"), daemon=True)
        t_err = threading.Thread(target=_read, args=(proc.stderr, stderr_lines, "stderr"), daemon=True)
        t_out.start(); t_err.start()
        try:
            exit_code = proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill(); exit_code = proc.wait()
        t_out.join(); t_err.join()

        full_out = "".join(stdout_lines); full_err = "".join(stderr_lines)
        combined = full_out + full_err
        risk = "critical" if "[SUCCESS]" in combined else "medium" if "0 of" in combined else "low"

        explain_tool_output(db, run_id=run_id, tool="hydra", target=target, command=argv, raw_output=full_out)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=combined, risk_level=risk)
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()
