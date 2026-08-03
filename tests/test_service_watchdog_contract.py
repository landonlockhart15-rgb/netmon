"""Contract tests for the Windows service watchdog installation."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestServiceWatchdogContract(unittest.TestCase):
    def test_watchdog_requires_expected_health_redirect_before_noop(self):
        script = (ROOT / "service_watchdog.ps1").read_text(encoding="utf-8")
        self.assertIn("/healthz", script)
        self.assertIn("StatusCode -eq 303", script)
        self.assertIn('Headers["Location"] -eq "/login"', script)
        self.assertIn("Start-ScheduledTask", script)

    def test_installer_schedules_watchdog_every_five_minutes(self):
        installer = (ROOT / "install_task.ps1").read_text(encoding="utf-8")
        self.assertIn('"NetMon Service Watchdog"', installer)
        self.assertIn("New-TimeSpan -Minutes 5", installer)
        self.assertIn("service_watchdog.ps1", installer)


if __name__ == "__main__":
    unittest.main()
