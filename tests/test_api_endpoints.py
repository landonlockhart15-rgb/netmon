"""
Standardized unit and integration tests for NetMon FastAPI API routes.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.database import get_db, Base
from models.tables import Setting, Device, ScanDevice, Scan


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        # Override AuthMiddleware session validation to bypass authentication during testing
        self.patch_auth = patch("app.main.validate_session", return_value=True)
        self.patch_auth.start()

        # Set up an isolated in-memory SQLite database for test runs using StaticPool
        # to share the single in-memory database connection across all sessions.
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Seed default settings in the test database
        self.db = self.Session()
        self.db.add(Setting(key="netmon_enabled", value="true"))
        self.db.add(Setting(key="health_check_interval_s", value="300"))
        self.db.add(Setting(key="health_target", value="8.8.8.8"))
        self.db.commit()

        # Override the get_db dependency of the FastAPI application
        def _override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()
        
        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        # Clean up overrides, db sessions, and mocks
        app.dependency_overrides.clear()
        self.db.close()
        self.engine.dispose()
        self.patch_auth.stop()

    def test_api_status(self):
        """Test GET /api/status route."""
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan", data)
        self.assertIn("ai", data)
        self.assertIn("capture", data)

    def test_get_settings(self):
        """Test GET /api/settings route."""
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("netmon_enabled"), "true")
        self.assertEqual(data.get("health_check_interval_s"), "300")

    def test_update_settings(self):
        """Test POST /api/settings route."""
        payload = {"netmon_enabled": "false", "health_check_interval_s": "120"}
        response = self.client.post("/api/settings", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("netmon_enabled", data.get("updated", []))
        self.assertIn("health_check_interval_s", data.get("updated", []))

        # Verify change persisted in DB
        response2 = self.client.get("/api/settings")
        data2 = response2.json()
        self.assertEqual(data2.get("netmon_enabled"), "false")
        self.assertEqual(data2.get("health_check_interval_s"), "120")

    def test_get_devices_empty(self):
        """Test GET /api/devices when there are no scans in DB."""
        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get("devices"), [])

    def test_get_devices_with_data(self):
        """Test GET /api/devices returns scanned devices."""
        # Insert a mock Scan and Device
        scan = Scan(id=1, status="complete")
        device = Device(id=1, mac="00:11:22:33:44:55", vendor="Apple")
        scan_device = ScanDevice(id=1, scan_id=1, device_id=1, ip="192.168.1.50", hostname="iphone")
        
        self.db.add(scan)
        self.db.add(device)
        self.db.add(scan_device)
        self.db.commit()

        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("devices", data)
        self.assertEqual(len(data["devices"]), 1)
        self.assertEqual(data["devices"][0]["ip"], "192.168.1.50")
        self.assertEqual(data["devices"][0]["vendor"], "Apple")


if __name__ == "__main__":
    unittest.main()
