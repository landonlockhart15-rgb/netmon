"""
Focused tests for app/main.py startup helpers.

Run from the project root:
    python -m unittest tests/test_app_main.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base
from app.main import _maybe_resume_capture
from models.tables import Setting


class TestMaybeResumeCapture(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        self.db = self.Session()
        self.db.add(Setting(key="capture_auto_start", value="true"))
        self.db.add(Setting(key="capture_enabled", value="false"))
        self.db.add(Setting(key="capture_interface", value=""))
        self.db.add(Setting(key="capture_file_size_mb", value="25"))
        self.db.add(Setting(key="capture_file_count", value="7"))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_uses_detected_interface(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_get_info.return_value = {"interface": "Wi-Fi"}
        mock_start.return_value = {"status": "started", "session_id": 123}

        _maybe_resume_capture()

        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args.kwargs["interface"], "Wi-Fi")
        self.assertEqual(mock_start.call_args.kwargs["file_size_mb"], 25)
        self.assertEqual(mock_start.call_args.kwargs["file_count"], 7)

        verify = self.Session()
        try:
            enabled = verify.query(Setting).filter(Setting.key == "capture_enabled").first()
            interface = verify.query(Setting).filter(Setting.key == "capture_interface").first()
        finally:
            verify.close()

        self.assertIsNotNone(enabled)
        self.assertEqual(enabled.value, "true")
        self.assertIsNotNone(interface)
        self.assertEqual(interface.value, "Wi-Fi")

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_uses_interface_name_as_fallback(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_get_info.return_value = {"interface_name": "Ethernet"}
        mock_start.return_value = {"status": "started", "session_id": 124}

        _maybe_resume_capture()

        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args.kwargs["interface"], "Ethernet")

        verify = self.Session()
        try:
            enabled = verify.query(Setting).filter(Setting.key == "capture_enabled").first()
            interface = verify.query(Setting).filter(Setting.key == "capture_interface").first()
        finally:
            verify.close()

        self.assertEqual(enabled.value, "true")
        self.assertEqual(interface.value, "Ethernet")

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_prefers_interface_over_interface_name(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_get_info.return_value = {"interface": "Wi-Fi", "interface_name": "Ethernet"}
        mock_start.return_value = {"status": "started", "session_id": 125}

        _maybe_resume_capture()

        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args.kwargs["interface"], "Wi-Fi")

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_with_empty_or_none_detected_interface(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_start.return_value = {"status": "started", "session_id": 126}

        for empty_val in [None, {}, {"interface": "", "interface_name": None}]:
            mock_get_info.return_value = empty_val
            mock_start.reset_mock()

            _maybe_resume_capture()
            mock_start.assert_not_called()

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_handles_exception_gracefully(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_get_info.side_effect = RuntimeError("Autodetect failed")
        mock_start.return_value = {"status": "started", "session_id": 127}

        # Should not raise exception
        _maybe_resume_capture()
        mock_start.assert_not_called()

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_handles_malformed_dict_gracefully(self, mock_sessionlocal, mock_get_info, mock_start):
        mock_sessionlocal.side_effect = self.Session
        mock_start.return_value = {"status": "started", "session_id": 128}

        for malformed in ["Wi-Fi", ["Wi-Fi"], 12345]:
            mock_get_info.return_value = malformed
            mock_start.reset_mock()

            # Should not raise exception (e.g. AttributeError on info.get)
            _maybe_resume_capture()
            mock_start.assert_not_called()

    @patch("traffic.capture.capture_engine.start")
    @patch("network.autodetect.get_network_info")
    @patch("app.database.SessionLocal")
    def test_auto_start_falls_back_to_db_interface(self, mock_sessionlocal, mock_get_info, mock_start):
        # If DB already has an interface, but autodetect returns nothing or fails,
        # it should start with the DB interface.
        db = self.Session()
        try:
            db_interface = db.query(Setting).filter(Setting.key == "capture_interface").first()
            db_interface.value = "DB-Interface"
            db.commit()
        finally:
            db.close()

        mock_sessionlocal.side_effect = self.Session
        mock_get_info.return_value = {}
        mock_start.return_value = {"status": "started", "session_id": 129}

        _maybe_resume_capture()

        mock_start.assert_called_once()
        self.assertEqual(mock_start.call_args.kwargs["interface"], "DB-Interface")


if __name__ == "__main__":
    unittest.main()
