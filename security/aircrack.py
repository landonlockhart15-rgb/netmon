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


def run_wifi_capture(*, run_id, interface, bssid=None, channel=None,
                     duration_seconds=60, distro="kali-linux", timeout_seconds=300):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        output_prefix = f"/tmp/netmon_capture_{run_id}"
        argv = [_wsl_exe(), "-d", distro, "--", "airodump-ng"]
        if bssid:
            argv += ["--bssid", bssid]
        if channel:
            argv += ["--channel", str(channel)]
        argv += ["--write", output_prefix, "--output-format", "pcap", interface]

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
            proc.wait(timeout=duration_seconds)
        except subprocess.TimeoutExpired:
            proc.terminate()
        exit_code = proc.wait()
        t_out.join(); t_err.join()

        full_out = "".join(stdout_lines); full_err = "".join(stderr_lines)
        append_output_chunk(db, run_id, stream="status",
                            content=f"\nCapture complete. File saved to {output_prefix}-01.cap in WSL.\n")
        explain_tool_output(db, run_id=run_id, tool="aircrack", target=bssid or interface,
                            command=argv, raw_output=full_out)
        mark_run_completed(db, run_id, status="succeeded", exit_code=exit_code,
                           raw_output_text=full_out + full_err, risk_level="info")
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()


def run_aircrack(*, run_id, capture_file_path, wordlist_file_path,
                 bssid=None, distro="kali-linux", timeout_seconds=1800):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        wsl_cap  = win_to_wsl(capture_file_path)
        wsl_wl   = win_to_wsl(wordlist_file_path)
        argv = [_wsl_exe(), "-d", distro, "--", "aircrack-ng"]
        if bssid:
            argv += ["-b", bssid]
        argv += ["-w", wsl_wl, wsl_cap]

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
        if "KEY FOUND" in full_out:
            risk = "critical"
        elif "Passphrase not in dictionary" in full_out:
            risk = "medium"
        else:
            risk = "low"

        explain_tool_output(db, run_id=run_id, tool="aircrack-ng", target=bssid or capture_file_path,
                            command=argv, raw_output=full_out)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=full_out + full_err, risk_level=risk)
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()
