import json
import subprocess
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy import func

from models.tables import SecurityToolRun, SecurityToolOutputChunk


def create_security_run(
    db,
    *,
    tool,
    tab=None,
    target=None,
    target_type=None,
    params=None,
    is_attack_tool=False,
    authorization_confirmed=False,
    device_id=None,
) -> int:
    run = SecurityToolRun(
        tool=tool,
        tab=tab,
        target=target,
        target_type=target_type,
        params_json=json.dumps(params) if params else None,
        is_attack_tool=is_attack_tool,
        authorization_confirmed=authorization_confirmed,
        device_id=device_id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run.id


def mark_run_started(db, run_id, *, command=None):
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if not run:
        return
    run.status = "running"
    run.started_at = datetime.now(timezone.utc)
    run.command_json = json.dumps(command) if command else None
    db.commit()


def append_output_chunk(db, run_id, *, stream, content):
    max_seq = (
        db.query(func.max(SecurityToolOutputChunk.sequence))
        .filter(SecurityToolOutputChunk.run_id == run_id)
        .scalar()
    )
    chunk = SecurityToolOutputChunk(
        run_id=run_id,
        sequence=(max_seq or 0) + 1,
        stream=stream,
        content=content,
    )
    db.add(chunk)
    db.commit()


def mark_run_completed(
    db,
    run_id,
    *,
    status,
    exit_code=None,
    raw_output_text=None,
    error_message=None,
    risk_level=None,
):
    run = db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()
    if not run:
        return
    completed_at = datetime.now(timezone.utc)
    run.completed_at = completed_at
    started = run.started_at
    if started and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    run.duration_seconds = (
        (completed_at - started).total_seconds() if started else None
    )
    run.status = status
    run.exit_code = exit_code
    run.raw_output_text = raw_output_text
    run.error_message = error_message
    run.risk_level = risk_level
    db.commit()


def get_run(db, run_id) -> Optional[SecurityToolRun]:
    return db.query(SecurityToolRun).filter(SecurityToolRun.id == run_id).first()


def run_subprocess_streaming(
    *,
    argv: list,
    timeout_seconds: int,
    on_stdout: Callable[[str], None],
    on_stderr: Callable[[str], None],
    cwd=None,
) -> tuple:
    stdout_chunks = []
    stderr_chunks = []

    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=cwd,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    def _read(stream, callback, chunks):
        try:
            for line in iter(stream.readline, ""):
                chunks.append(line)
                callback(line)
        finally:
            stream.close()

    t_out = threading.Thread(target=_read, args=(process.stdout, on_stdout, stdout_chunks), daemon=True)
    t_err = threading.Thread(target=_read, args=(process.stderr, on_stderr, stderr_chunks), daemon=True)
    t_out.start()
    t_err.start()

    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        exit_code = process.wait()

    t_out.join()
    t_err.join()

    return exit_code, "".join(stdout_chunks), "".join(stderr_chunks)
