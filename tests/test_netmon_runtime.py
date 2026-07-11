"""Focused tests for packaged startup preflight and first-run onboarding."""

import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import netmon_runtime as runtime


class RuntimeOnboardingTests(unittest.TestCase):
    def test_find_nmap_uses_path_first(self):
        with patch.object(runtime.shutil, "which", return_value=r"C:\Tools\nmap.exe"):
            self.assertEqual(runtime.find_nmap(), r"C:\Tools\nmap.exe")

    def test_find_nmap_checks_standard_install_folders(self):
        with patch.object(runtime.shutil, "which", return_value=None), patch.object(
            Path, "is_file", autospec=True, side_effect=lambda path: "Program Files\\Nmap" in str(path)
        ):
            with patch.dict(os.environ, {"ProgramFiles": r"D:\Program Files"}, clear=False):
                self.assertEqual(runtime.find_nmap(), r"D:\Program Files\Nmap\nmap.exe")

    def test_nmap_preflight_is_quiet_when_available(self):
        with patch.object(runtime, "find_nmap", return_value=r"C:\Nmap\nmap.exe"), patch.object(
            runtime.webbrowser, "open"
        ) as open_browser:
            self.assertTrue(runtime.show_nmap_preflight())
            open_browser.assert_not_called()

    def test_first_run_note_explains_browser_and_safe_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env"
            with patch.dict(os.environ, {"APP_USERNAME": "", "APP_PASSWORD_HASH": ""}, clear=False):
                credentials = runtime._ensure_password(env_path)

            self.assertIsNotNone(credentials)
            note = (Path(tmp) / "FIRST-RUN-LOGIN.txt").read_text(encoding="utf-8")
            self.assertIn("http://localhost:8000", note)
            self.assertIn("Delete it after", note)
            self.assertNotIn(credentials[1], env_path.read_text(encoding="utf-8"))

    def test_clipboard_uses_stdin_not_command_line(self):
        with patch.object(runtime.subprocess, "run") as run:
            self.assertTrue(runtime._copy_to_clipboard("secret"))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["clip.exe"])
        self.assertNotIn("secret", args[0])
        self.assertIn("secret", kwargs["input"])

    def test_first_run_consent_copies_only_paste_ready_password(self):
        with patch("ctypes.windll.user32.MessageBoxW", return_value=6), patch.object(
            runtime, "_copy_to_clipboard"
        ) as copy:
            runtime.show_first_run_dialog("admin", "paste-ready-secret")
        copy.assert_called_once_with("paste-ready-secret")

    def test_dialog_failure_does_not_log_plaintext_password(self):
        output = StringIO()
        with patch("ctypes.windll.user32.MessageBoxW", side_effect=OSError("no dialog")), patch(
            "sys.stdout", output
        ):
            runtime.show_first_run_dialog("admin", "do-not-log-this")
        self.assertNotIn("do-not-log-this", output.getvalue())
        self.assertIn("FIRST-RUN-LOGIN.txt", output.getvalue())


if __name__ == "__main__":
    unittest.main()
