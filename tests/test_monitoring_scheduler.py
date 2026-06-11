"""
Focused unit tests for monitoring/scheduler.py helper functions.

Run from the project root:
    python -m unittest tests/test_monitoring_scheduler.py -v
"""
import os
import sys
import unittest
import json
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.tables import Base, Setting
from monitoring.scheduler import (
    _get_str,
    _get_float,
    _get_int,
    _netmon_enabled,
)


class TestSchedulerHelpers(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.close()

    def test_get_str(self):
        # Default value
        self.assertEqual(_get_str(self.session, "test_key", "default_val"), "default_val")

        # Set value
        s = Setting(key="test_key", value="custom_val")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_str(self.session, "test_key", "default_val"), "custom_val")

    def test_get_float(self):
        # Default value
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 3.14)

        # Valid float
        s = Setting(key="float_key", value="5.55")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 5.55)

        # Invalid float reverts to default
        s.value = "not-a-float"
        self.session.commit()
        self.assertEqual(_get_float(self.session, "float_key", 3.14), 3.14)

    def test_get_int(self):
        # Default value
        self.assertEqual(_get_int(self.session, "int_key", 42), 42)

        # Valid int
        s = Setting(key="int_key", value="100")
        self.session.add(s)
        self.session.commit()
        self.assertEqual(_get_int(self.session, "int_key", 42), 100)

        # Invalid int reverts to default
        s.value = "not-an-int"
        self.session.commit()
        self.assertEqual(_get_int(self.session, "int_key", 42), 42)

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_setting_disabled(self, mock_path):
        # Setting netmon_enabled to false
        s = Setting(key="netmon_enabled", value="false")
        self.session.add(s)
        self.session.commit()
        self.assertFalse(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_setting_enabled_no_maintenance(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file fails to read or has no services
        mock_path.read_text.side_effect = Exception("File not found")
        self.assertTrue(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_maintenance_disabled(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file says netmon is disabled
        mock_path.read_text.return_value = json.dumps({
            "services": {
                "netmon": {
                    "disabled": True
                }
            }
        })
        self.assertFalse(_netmon_enabled(self.session))

    @patch("monitoring.scheduler.AI_HUB_MAINTENANCE_FILE")
    def test_netmon_enabled_maintenance_not_disabled(self, mock_path):
        # Setting netmon_enabled to true
        s = Setting(key="netmon_enabled", value="true")
        self.session.add(s)
        self.session.commit()

        # Maintenance file says netmon is NOT disabled
        mock_path.read_text.return_value = json.dumps({
            "services": {
                "netmon": {
                    "disabled": False
                }
            }
        })
        self.assertTrue(_netmon_enabled(self.session))


if __name__ == "__main__":
    unittest.main()
