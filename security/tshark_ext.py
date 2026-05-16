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


def run_tshark_capture(*, run_id, interface, duration_seconds=60,
                       capture_filter=None, distro="kali-linux", timeout_seconds=300):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        output_path = f"/tmp/netmon_tshark_{run_id}.pcap"
        argv = [_wsl_exe(), "-d", distro, "--", "tshark", "-i", interface,
                "-a", f"duration:{duration_seconds}", "-w", output_path]
        if capture_filter:
            argv += ["-f", capture_filter]

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
            exit_code = proc.wait(timeout=duration_seconds + 30)
        except subprocess.TimeoutExpired:
            proc.kill(); exit_code = proc.wait()
        t_out.join(); t_err.join()

        full_out = "".join(stdout_lines); full_err = "".join(stderr_lines)
        append_output_chunk(db, run_id, stream="status",
                            content=f"\nCapture saved to {output_path} in WSL.\n")
        explain_tool_output(db, run_id=run_id, tool="tshark", target=interface,
                            command=argv, raw_output=full_err)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=full_out + full_err, risk_level="info")
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()


def run_tshark_analyze(*, run_id, pcap_file_path, distro="kali-linux", timeout_seconds=300):
    from app.database import SessionLocal
    from api.routes import _running_procs
    db = SessionLocal()
    try:
        wsl_pcap = win_to_wsl(pcap_file_path)
        argv = [_wsl_exe(), "-d", distro, "--", "tshark", "-r", wsl_pcap, "-q", "-z", "io,phs"]

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
        explain_tool_output(db, run_id=run_id, tool="tshark", target=pcap_file_path,
                            command=argv, raw_output=full_out)
        mark_run_completed(db, run_id, status="succeeded" if exit_code == 0 else "failed",
                           exit_code=exit_code, raw_output_text=full_out + full_err, risk_level="info")
    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception: pass
    finally:
        _running_procs.pop(run_id, None); db.close()
