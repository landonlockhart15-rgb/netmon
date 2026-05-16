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


def run_john(*, run_id, hash_file_path, wordlist_file_path=None,
             format_name=None, distro="kali-linux", max_runtime_seconds=900):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        wsl_hash = win_to_wsl(hash_file_path)
        argv = [_wsl_exe(), "-d", distro, "--", "john"]
        if wordlist_file_path:
            argv.append(f"--wordlist={win_to_wsl(wordlist_file_path)}")
        if format_name and format_name != "auto":
            argv.append(f"--format={format_name}")
        argv += [f"--max-run-time={max_runtime_seconds}", wsl_hash]

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
            exit_code = proc.wait(timeout=max_runtime_seconds + 30)
        except subprocess.TimeoutExpired:
            proc.kill(); exit_code = proc.wait()
        t_out.join(); t_err.join()
        full_out = "".join(stdout_lines); full_err = "".join(stderr_lines)

        # Run --show to get cracked count
        show_result = subprocess.run(
            [_wsl_exe(), "-d", distro, "--", "john", "--show", wsl_hash],
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        show_out = show_result.stdout
        append_output_chunk(db, run_id, stream="stdout", content="\n--- Cracked passwords ---\n" + show_out)

        cracked = 0
        for line in show_out.splitlines():
            if "password hash" in line.lower() or "password cracked" in line.lower():
                try: cracked = int(line.split()[0])
                except (ValueError, IndexError): pass

        risk = "high" if cracked > 0 else "medium"

        explain_tool_output(db, run_id=run_id, tool="john", target=hash_file_path,
                            command=argv, raw_output=full_out + "\n" + show_out)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=full_out + full_err, risk_level=risk)
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()
