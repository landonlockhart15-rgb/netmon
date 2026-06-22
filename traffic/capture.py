"""
traffic/capture.py — Passive ring-buffer capture engine.

Wraps dumpcap (from Wireshark) which writes a rolling ring buffer of
pcapng files to data/captures/. The capture is entirely passive —
we only read packets off the wire, we never inject or modify traffic.

Ring-buffer behaviour:
  dumpcap -b filesize:N -b files:M  writes up to M files of size N KB,
  then wraps around and overwrites the oldest file. Disk use is bounded.

Thread safety:
  A single threading.Lock protects all mutable state.
  Routes and the background scheduler both call this safely.

Visibility note (shown in the UI):
  On a typical switched home network this machine can only see:
    - Its own traffic (sent and received)
    - Broadcast / multicast traffic (ARP, mDNS, DHCP, etc.)
  Traffic between OTHER devices goes through the switch and is NOT
  visible here unless port mirroring is configured on the router.
  This is by design — home switches do not forward all traffic.
"""

import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from traffic.interfaces import find_tool, _no_window

CAPTURE_DIR = Path("data/captures")


class CaptureEngine:
    """Manages one dumpcap ring-buffer capture subprocess."""

    def __init__(self):
        self._proc:       Optional[subprocess.Popen] = None
        self._session_id: Optional[int]              = None
        self._interface:  Optional[str]              = None
        self._started_at: Optional[datetime]         = None
        self._error:      Optional[str]              = None
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(
        self,
        interface:    str,
        file_size_mb: int = 10,
        file_count:   int = 5,
        session_factory=None,
    ) -> Dict:
        with self._lock:
            if self._is_running():
                return {"status": "already_running", "session_id": self._session_id}

            dumpcap = find_tool("dumpcap")
            if not dumpcap:
                self._error = (
                    "dumpcap not found — install Wireshark with Npcap to enable capture"
                )
                return {"status": "error", "message": self._error}

            CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            base_path = str(CAPTURE_DIR / "ring.pcapng")

            # dumpcap -b filesize takes kilobytes
            cmd = [
                dumpcap,
                "-i", interface,
                "-b", f"filesize:{file_size_mb * 1024}",
                "-b", f"files:{file_count}",
                "-w", base_path,
                "-q",   # suppress per-packet stdout noise
            ]

            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    creationflags=_no_window(),
                )
            except FileNotFoundError:
                msg = f"Could not launch dumpcap at: {dumpcap}"
                self._error = msg
                return {"status": "error", "message": msg}
            except Exception as e:
                self._error = str(e)
                return {"status": "error", "message": str(e)}

            self._interface  = interface
            self._started_at = datetime.now(timezone.utc)
            self._error      = None

            session_id = self._write_session(
                session_factory, interface, file_size_mb, file_count, base_path
            )
            self._session_id = session_id
            print(f"[capture] Started on interface '{interface}' — session #{session_id}")
            return {"status": "started", "session_id": session_id}

    def stop(self, session_factory=None) -> Dict:
        with self._lock:
            if not self._proc:
                return {"status": "not_running"}

            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            except Exception:
                pass

            self._proc = None
            old_id = self._session_id

            if old_id and session_factory:
                self._close_session(session_factory, old_id, "stopped")

            self._session_id = None
            self._interface  = None
            self._started_at = None
            print(f"[capture] Stopped — session #{old_id}")
            return {"status": "stopped", "session_id": old_id}

    def get_status(self) -> Dict:
        with self._lock:
            running = self._is_running()
            return {
                "running":    running,
                "capturing":  running,
                "session_id": self._session_id,
                "interface":  self._interface,
                "started_at": (
                    self._started_at.isoformat() if self._started_at else None
                ),
                "error":      self._error,
                "capture_dir": str(CAPTURE_DIR.resolve()),
            }

    def check_alive(self, session_factory=None):
        """
        Called periodically by the scheduler.
        Detects unexpected dumpcap exit and updates the DB session record.
        """
        with self._lock:
            if self._proc and self._proc.poll() is not None:
                rc = self._proc.returncode
                stderr = b""
                try:
                    stderr = self._proc.stderr.read() or b""
                except Exception:
                    pass
                msg = f"dumpcap exited (code {rc}): {stderr.decode('utf-8', errors='replace')[:200]}".strip()
                self._error = msg
                self._proc  = None
                print(f"[capture] {msg}")

                if self._session_id and session_factory:
                    self._close_session(session_factory, self._session_id, "error", msg)

                self._session_id = None
                self._interface  = None
                self._started_at = None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _is_running(self) -> bool:
        """Must be called with self._lock held."""
        return self._proc is not None and self._proc.poll() is None

    def _write_session(self, factory, interface, file_size_mb, file_count, path) -> Optional[int]:
        if not factory:
            return None
        try:
            from models.tables import CaptureSession
            db = factory()
            sess = CaptureSession(
                interface=interface,
                status="running",
                file_path=path,
                file_size_mb=file_size_mb,
                file_count=file_count,
            )
            db.add(sess)
            db.commit()
            db.refresh(sess)
            sid = sess.id
            db.close()
            return sid
        except Exception as e:
            print(f"[capture] DB write error: {e}")
            return None

    def _close_session(self, factory, session_id, status, error=None):
        try:
            from models.tables import CaptureSession
            db = factory()
            sess = db.query(CaptureSession).filter(
                CaptureSession.id == session_id
            ).first()
            if sess and sess.status == "running":
                sess.status     = status
                sess.stopped_at = datetime.now(timezone.utc)
                if error:
                    sess.error = error
                db.commit()
            db.close()
        except Exception as e:
            print(f"[capture] DB close-session error: {e}")


# ── Global singleton ──────────────────────────────────────────────────────────
# Imported by api/routes.py and monitoring/scheduler.py
capture_engine = CaptureEngine()
