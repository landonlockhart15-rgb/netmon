"""Release-version consistency checks."""

import re
import unittest
from pathlib import Path

from app.main import app
from app.version import __version__


class VersionTests(unittest.TestCase):
    def test_version_is_semver_and_used_by_fastapi(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(app.version, __version__)

    def test_installer_requires_build_supplied_version(self):
        script = Path("installer/netmon.iss").read_text(encoding="utf-8")
        self.assertIn("#ifndef AppVersion", script)
        self.assertNotRegex(script, re.compile(r'#define AppVersion\s+"\d+\.\d+\.\d+"'))


if __name__ == "__main__":
    unittest.main()
