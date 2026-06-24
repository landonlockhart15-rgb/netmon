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
from scanner.parser import parse_nmap_xml


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

    def test_parse_nmap_xml_maps_banner_cves(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.10" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.49"/>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml)
        self.assertEqual(devices[0]["services"][0]["product"], "Apache httpd")
        self.assertEqual(devices[0]["vulnerabilities"][0]["cve"], "CVE-2021-41773")

    def test_parse_nmap_xml_maps_vulners_cves(self):
        # nmap --script vulners embeds CVEs as a <script id="vulners"> table.
        xml = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.11" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.2p1"/>
            <script id="vulners" output="ignored">
              <table key="cpe:/a:openbsd:openssh:8.2p1">
                <table>
                  <elem key="id">CVE-2020-15778</elem>
                  <elem key="cvss">7.8</elem>
                  <elem key="type">cve</elem>
                  <elem key="is_exploit">true</elem>
                </table>
                <table>
                  <elem key="id">EDB-ID:12345</elem>
                  <elem key="cvss">7.8</elem>
                  <elem key="type">exploitdb</elem>
                </table>
              </table>
            </script>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml)
        vulns = devices[0]["vulnerabilities"]
        # Exactly one CVE kept (the exploit-db row is filtered out).
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]["cve"], "CVE-2020-15778")
        self.assertEqual(vulns[0]["risk"], "high")
        self.assertEqual(vulns[0]["source"], "vulners")
        self.assertTrue(vulns[0]["exploit_available"])

    def test_parse_nmap_xml_vulners_dedupes_offline_cve(self):
        # When vulners reports a CVE the offline mapper already flags, it must
        # not be listed twice.
        xml = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.12" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.49"/>
            <script id="vulners">
              <table key="cpe:/a:apache:http_server:2.4.49">
                <table>
                  <elem key="id">CVE-2021-41773</elem>
                  <elem key="cvss">9.8</elem>
                  <elem key="type">cve</elem>
                </table>
              </table>
            </script>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml)
        cves = [v["cve"] for v in devices[0]["vulnerabilities"]]
        self.assertEqual(cves.count("CVE-2021-41773"), 1)

    def test_cve_mapping_endpoint(self):
        scan = Scan(id=1, status="complete")
        device = Device(id=1, mac="00:11:22:33:44:55", vendor="Lab")
        scan_device = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.10",
            hostname="lab-web", open_ports="[80]",
            services_json='[{"port":80,"service":"http","product":"Apache httpd","version":"2.4.49"}]',
            cves_json='[{"cve":"CVE-2021-41773","risk":"critical","title":"Apache httpd path traversal","port":80,"service":"http","recommendation":"Upgrade Apache httpd to 2.4.51 or newer."}]',
        )
        self.db.add(scan)
        self.db.add(device)
        self.db.add(scan_device)
        self.db.commit()

        response = self.client.get("/api/security/cve-mapping")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["finding_count"], 1)
        self.assertEqual(data["findings"][0]["cve"], "CVE-2021-41773")
        self.assertEqual(data["findings"][0]["ip"], "192.168.1.10")

    def test_attack_tree_endpoint_maps_iot_to_nas_path(self):
        scan = Scan(id=1, status="complete")
        iot = Device(id=1, mac="00:11:22:33:44:55", vendor="Wyze", label="Garage Camera", is_known=False)
        nas = Device(id=2, mac="00:11:22:33:44:66", vendor="Synology", label="Family NAS", is_known=True)
        iot_sd = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.20",
            hostname="garage-cam", open_ports="[80, 23]",
            cves_json='[{"cve":"CVE-2020-0001","risk":"high","port":80,"service":"http"}]',
        )
        nas_sd = ScanDevice(
            id=2, scan_id=1, device_id=2, ip="192.168.1.30",
            hostname="nas", open_ports="[445, 5000]",
        )
        self.db.add(scan)
        self.db.add(iot)
        self.db.add(nas)
        self.db.add(iot_sd)
        self.db.add(nas_sd)
        self.db.commit()

        response = self.client.get("/api/security/attack-tree")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["path_count"], 1)
        path = data["paths"][0]
        self.assertEqual(path["source"]["ip"], "192.168.1.20")
        self.assertEqual(path["target"]["ip"], "192.168.1.30")
        self.assertGreaterEqual(len(path["steps"]), 3)
        self.assertGreaterEqual(len(path["mitigations"]), 1)

    @patch("ai.provider.get_investigation_provider")
    def test_explain_chat_turn(self, mock_get_provider):
        """Test POST /api/device/{device_id}/chat/{turn_id}/explain route."""
        scan = Scan(id=1, status="complete")
        device = Device(id=1, mac="00:11:22:33:44:55", vendor="Apple")
        from models.tables import DeviceChat
        turn = DeviceChat(id=42, device_id=1, role="assistant", content="Looks like an Apple device.")

        self.db.add(scan)
        self.db.add(device)
        self.db.add(turn)
        self.db.commit()

        mock_provider = MagicMock()
        mock_provider.name = "gemini"
        mock_provider.analyze.return_value = {
            "raw_response": "This message indicates it is an Apple device based on OUI prefix.",
            "error": None
        }
        mock_get_provider.return_value = mock_provider

        response = self.client.post("/api/device/1/chat/42/explain")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("explanation", data)
        self.assertEqual(data["explanation"], "This message indicates it is an Apple device based on OUI prefix.")

    def test_login_page(self):
        """Test GET /login serves the login page."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)

    @patch("api.auth_routes.check_credentials")
    def test_auth_login_success(self, mock_check):
        """Test POST /auth/login with valid credentials redirects with cookie."""
        mock_check.return_value = True
        response = self.client.post("/auth/login", data={"username": "admin", "password": "password"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers.get("location"), "/")
        self.assertIn("netmon_session", response.cookies)

    @patch("api.auth_routes.check_credentials")
    def test_auth_login_failure(self, mock_check):
        """Test POST /auth/login with invalid credentials redirects back to login."""
        mock_check.return_value = False
        response = self.client.post("/auth/login", data={"username": "wrong", "password": "wrong"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(
            response.headers.get("location", "").endswith("/login?error=invalid") or
            response.headers.get("location", "").endswith("/login?error=not_configured")
        )

    @patch("api.auth_routes.revoke_session")
    def test_auth_logout(self, mock_revoke):
        """Test GET /auth/logout invalidates session and redirects."""
        self.client.cookies.set("netmon_session", "fake_token")
        response = self.client.get("/auth/logout", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers.get("location"), "/login")
        mock_revoke.assert_called_once_with("fake_token")

    def test_update_device(self):
        """Test PATCH /api/device/{device_id} to update labels/trust."""
        import json
        device = Device(id=42, mac="11:22:33:44:55:66", vendor="Dell", label="Original", is_known=False)
        self.db.add(device)
        self.db.commit()

        payload = {"label": "Updated", "is_known": True, "allow": {"allowed_ports": [22, 80]}}
        response = self.client.patch("/api/device/42", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], 42)
        self.assertEqual(data["label"], "Updated")
        self.assertEqual(data["is_known"], True)
        self.assertEqual(data["allow"]["allowed_ports"], [22, 80])

        db_device = self.db.query(Device).filter(Device.id == 42).first()
        self.assertEqual(db_device.label, "Updated")
        self.assertEqual(db_device.is_known, True)
        self.assertEqual(json.loads(db_device.allow_json)["allowed_ports"], [22, 80])

    def test_update_device_not_found(self):
        """Test PATCH /api/device/{device_id} returns 404 if device not found."""
        response = self.client.patch("/api/device/999", json={"label": "Ghost"})
        self.assertEqual(response.status_code, 404)

    def test_add_device_allow_entry(self):
        """Test POST /api/device/{device_id}/allow adds rules to allowed behavior."""
        device = Device(id=10, mac="00:aa:bb:cc:dd:ee")
        self.db.add(device)
        self.db.commit()

        # Append port 443
        response = self.client.post("/api/device/10/allow", json={"port": 443})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allow"]["allowed_ports"], [443])

        # Append country US
        response = self.client.post("/api/device/10/allow", json={"country": "US"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allow"]["allowed_countries"], ["US"])

        # Append destination 8.8.8.8
        response = self.client.post("/api/device/10/allow", json={"destination": "8.8.8.8"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allow"]["allowed_destinations"], ["8.8.8.8"])

        # Set high_bandwidth
        response = self.client.post("/api/device/10/allow", json={"high_bandwidth": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["allow"]["allowed_high_bandwidth"], True)

    @patch("ai.provider.get_investigation_provider")
    def test_contextual_insight(self, mock_get_provider):
        """Test POST /api/ai/contextual-insight route."""
        self.db.add(Setting(key="ai_enabled", value="true"))
        self.db.commit()

        mock_provider = MagicMock()
        mock_provider.name = "gemini"
        mock_provider.analyze.return_value = {
            "raw_response": "What happened: An offline event was detected. Why it matters: This means the local gateway is unreachable.",
            "error": None
        }
        mock_get_provider.return_value = mock_provider

        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down", "context": "outage"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("explanation", data)
        self.assertEqual(data["explanation"], "What happened: An offline event was detected. Why it matters: This means the local gateway is unreachable.")

    @patch("ai.provider.get_investigation_provider")
    def test_contextual_insight_validation(self, mock_get_provider):
        """Test POST /api/ai/contextual-insight validation rules."""
        self.db.add(Setting(key="ai_enabled", value="true"))
        self.db.commit()

        mock_provider = MagicMock()
        mock_provider.name = "gemini"
        mock_get_provider.return_value = mock_provider

        # 1. Missing text
        response = self.client.post("/api/ai/contextual-insight", json={"context": "outage"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("text is required", response.json()["detail"])

        # 2. Text not a string
        response = self.client.post("/api/ai/contextual-insight", json={"text": 12345, "context": "outage"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("text must be a string", response.json()["detail"])

        # 3. Text empty/whitespace only
        response = self.client.post("/api/ai/contextual-insight", json={"text": "   ", "context": "outage"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("text cannot be empty", response.json()["detail"])

        # 4. Text too long
        response = self.client.post("/api/ai/contextual-insight", json={"text": "a" * 5001, "context": "outage"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("text parameter exceeds maximum length", response.json()["detail"])

        # 5. Context not a string
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down", "context": ["not", "string"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("context must be a string", response.json()["detail"])

        # 6. Context too long
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down", "context": "b" * 5001})
        self.assertEqual(response.status_code, 400)
        self.assertIn("context parameter exceeds maximum length", response.json()["detail"])

    @patch("ai.provider.get_investigation_provider")
    def test_contextual_insight_error_handling(self, mock_get_provider):
        """Test POST /api/ai/contextual-insight AI provider error handling."""
        self.db.add(Setting(key="ai_enabled", value="true"))
        self.db.commit()

        mock_provider = MagicMock()
        mock_provider.name = "gemini"
        mock_get_provider.return_value = mock_provider

        # 1. Provider returns dictionary with error key
        mock_provider.analyze.return_value = {"error": "API Key Invalid"}
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down"})
        self.assertEqual(response.status_code, 500)
        self.assertIn("AI error: API Key Invalid", response.json()["detail"])

        # 2. Provider throws an exception
        mock_provider.analyze.side_effect = Exception("Connection timed out")
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down"})
        self.assertEqual(response.status_code, 500)
        self.assertIn("AI analysis failed to execute: Connection timed out", response.json()["detail"])
        mock_provider.analyze.side_effect = None

        # 3. Provider returns non-dict
        mock_provider.analyze.return_value = "invalid response type"
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down"})
        self.assertEqual(response.status_code, 500)
        self.assertIn("AI provider returned an invalid response format", response.json()["detail"])

        # 4. Provider returns non-string explanation
        mock_provider.analyze.return_value = {"raw_response": 12345}
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down"})
        self.assertEqual(response.status_code, 500)
        self.assertIn("AI provider returned a non-string explanation", response.json()["detail"])

        # 5. Provider returns empty response
        mock_provider.analyze.return_value = {"raw_response": "   "}
        response = self.client.post("/api/ai/contextual-insight", json={"text": "Connection down"})
        self.assertEqual(response.status_code, 500)
        self.assertIn("AI returned an empty explanation", response.json()["detail"])

    def test_route_security_discovery(self):
        """
        Dynamically discover all registered routes in the FastAPI app
        and verify they conform to the security policies defined in AuthMiddleware:
          1. Exempt paths (/login, /auth/login, /auth/logout) bypass validation.
          2. Non-exempt /api/* routes must return 401 JSON.
          3. Other non-exempt routes (like UI pages/static files) must redirect (303) to /login.
        """
        # Create a clean client without the authentication patch
        unpatched_client = TestClient(app)
        self.patch_auth.stop()
        try:
            exempt_paths = {"/login", "/auth/login", "/auth/logout"}
            
            import re
            def get_concrete_path(route_path: str) -> str:
                def replacer(match):
                    param = match.group(1)
                    if "full_path" in param:
                        return "index.html"
                    return "1"
                return re.sub(r"\{([^}]+)\}", replacer, route_path)
            
            for route in app.routes:
                route_path = getattr(route, "path", None)
                if not route_path:
                    continue
                
                methods = getattr(route, "methods", None) or ["GET"]
                concrete_path = get_concrete_path(route_path)
                
                for method in methods:
                    response = unpatched_client.request(method, concrete_path, follow_redirects=False)
                    
                    if concrete_path in exempt_paths:
                        self.assertNotEqual(response.status_code, 401, f"Exempt path {concrete_path} returned 401")
                    elif concrete_path.startswith("/api/"):
                        self.assertEqual(
                            response.status_code, 401,
                            f"API route {concrete_path} [{method}] was not protected by AuthMiddleware (returned {response.status_code})"
                        )
                        self.assertEqual(response.json(), {"detail": "Not authenticated"})
                    else:
                        self.assertEqual(
                            response.status_code, 303,
                            f"UI/Static route {concrete_path} [{method}] did not redirect to /login (returned {response.status_code})"
                        )
                        self.assertEqual(response.headers.get("location"), "/login")
        finally:
            self.patch_auth.start()


if __name__ == "__main__":
    unittest.main()

