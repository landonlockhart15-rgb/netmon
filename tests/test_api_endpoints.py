"""
Standardized unit and integration tests for NetMon FastAPI API routes.
"""
import os
import sys
import unittest
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.database import get_db, Base
from models.tables import Setting, Device, ScanDevice, Scan, ActivityLog
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
        scan_device = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.50", hostname="iphone",
            services_json='[{"name": "http"}]',
            cves_json='[{"cve": "CVE-2014-0160", "risk": "critical"}]'
        )
        
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
        self.assertEqual(data["devices"][0]["vulnerability_count"], 1)
        self.assertEqual(data["devices"][0]["max_cve_risk"], "critical")

    def test_get_devices_uses_latest_security_snapshot_and_highest_risk(self):
        """Test GET /api/devices prefers the newest scan and the strongest CVE risk."""
        old_scan = Scan(
            id=1,
            status="complete",
            started_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        new_scan = Scan(
            id=2,
            status="complete",
            started_at=datetime.now(timezone.utc),
        )
        patched = Device(id=1, mac="00:11:22:33:44:55", vendor="Apple", label="Patched Host")
        mixed = Device(id=2, mac="00:11:22:33:44:66", vendor="Dell", label="Mixed Host")
        patched_old = ScanDevice(
            id=1,
            scan_id=1,
            device_id=1,
            ip="192.168.1.20",
            hostname="patched-old",
            services_json='[{"name": "https"}]',
            cves_json='[{"cve": "CVE-2014-0160", "risk": "critical"}]',
        )
        patched_new = ScanDevice(
            id=2,
            scan_id=2,
            device_id=1,
            ip="192.168.1.20",
            hostname="patched-new",
            services_json='[{"name": "https"}]',
            cves_json='[]',
        )
        mixed_sd = ScanDevice(
            id=3,
            scan_id=2,
            device_id=2,
            ip="192.168.1.21",
            hostname="mixed-host",
            services_json='[{"name": "ssh"}]',
            cves_json='[{"cve": "CVE-0000-1"}, {"cve": "CVE-0000-2", "risk": "low"}, {"cve": "CVE-0000-3", "risk": "High"}]',
        )
        self.db.add_all([old_scan, new_scan, patched, mixed, patched_old, patched_new, mixed_sd])
        self.db.commit()

        response = self.client.get("/api/devices")
        self.assertEqual(response.status_code, 200)
        data = response.json()["devices"]
        by_ip = {device["ip"]: device for device in data}

        self.assertEqual(by_ip["192.168.1.20"]["vulnerability_count"], 0)
        self.assertIsNone(by_ip["192.168.1.20"]["max_cve_risk"])
        self.assertEqual(by_ip["192.168.1.20"]["hostname"], "patched-new")
        self.assertEqual(by_ip["192.168.1.21"]["vulnerability_count"], 3)
        self.assertEqual(by_ip["192.168.1.21"]["max_cve_risk"], "High")
        self.assertEqual([device["ip"] for device in data], sorted(by_ip.keys()))

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

    def test_map_service_vulnerabilities_conservative_extended(self):
        # 1. Heartbleed (CVE-2014-0160) - OpenSSL 1.0.1e
        xml_heartbleed = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.10" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="443">
            <state state="open"/>
            <service name="https" product="OpenSSL" version="1.0.1e"/>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml_heartbleed)
        self.assertEqual(devices[0]["vulnerabilities"][0]["cve"], "CVE-2014-0160")

        # 2. EternalBlue (CVE-2017-0144) - Microsoft Windows 7 SMB
        xml_eternal = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.10" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds" product="Microsoft Windows 7 microsoft-ds"/>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml_eternal)
        self.assertEqual(devices[0]["vulnerabilities"][0]["cve"], "CVE-2017-0144")

        # 3. BlueKeep (CVE-2019-0708) - Microsoft Windows 7 RDP
        xml_bluekeep = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.10" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="3389">
            <state state="open"/>
            <service name="ms-wbt-server" product="Microsoft Windows 7 RDP"/>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml_bluekeep)
        self.assertEqual(devices[0]["vulnerabilities"][0]["cve"], "CVE-2019-0708")

        # 4. Conservative check: Linux running Samba on 445 should NOT map to EternalBlue
        xml_samba = """<?xml version="1.0"?>
        <nmaprun><host>
          <status state="up"/>
          <address addr="192.168.1.10" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="445">
            <state state="open"/>
            <service name="microsoft-ds" product="Samba smbd" version="4.15.13"/>
          </port></ports>
        </host></nmaprun>"""
        devices = parse_nmap_xml(xml_samba)
        self.assertEqual(len(devices[0]["vulnerabilities"]), 0)

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
            services_json='[{"port": 80, "service": "http"}]',
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
        path = data["verified_paths"][0]
        self.assertEqual(path["source"]["ip"], "192.168.1.20")
        self.assertEqual(path["target"]["ip"], "192.168.1.30")
        self.assertGreaterEqual(len(path["steps"]), 3)
        self.assertGreaterEqual(len(path["mitigations"]), 1)

    def test_least_resistance_endpoint_maps_ports_to_cves(self):
        scan = Scan(id=1, status="complete")
        dev = Device(id=1, mac="00:11:22:33:44:55", vendor="Wyze", label="Garage Camera", is_known=False)
        sd = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.20",
            hostname="garage-cam", open_ports="[445]",
            services_json='[{"port":445,"service":"microsoft-ds"}]',
            cves_json='[{"cve":"CVE-2017-0144","risk":"critical","title":"Microsoft Windows SMB Remote Code Execution (EternalBlue)","port":445,"service":"microsoft-ds","recommendation":"Apply security update MS17-010 and disable SMBv1.","source":"vulners"}]',
        )
        self.db.add(scan)
        self.db.add(dev)
        self.db.add(sd)
        self.db.commit()

        response = self.client.get("/api/security/least-resistance")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["scan"]["id"], 1)
        self.assertEqual(len(data["hosts"]), 1)
        host = data["hosts"][0]
        self.assertEqual(host["ip"], "192.168.1.20")
        self.assertEqual(host["overall_risk"], "critical")
        self.assertEqual(host["open_ports"], [445])
        self.assertEqual(len(host["mapped_cves"]), 1)
        self.assertEqual(host["mapped_cves"][0]["cve"], "CVE-2017-0144")
        self.assertEqual(host["mapped_cves"][0]["source"], "vulners")
        self.assertEqual(
            [step["title"] for step in host["least_resistance_path"]["steps"]],
            ["LAN Reconnaissance", "Service Exploitation", "Host Compromise"],
        )
        self.assertEqual(len(host["least_resistance_path"]["steps"]), 3)

    def test_least_resistance_endpoint_handles_empty_dataset(self):
        response = self.client.get("/api/security/least-resistance")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNone(data["scan"]["id"])
        self.assertEqual(data["hosts"], [])

    def test_least_resistance_endpoint_uses_latest_scan_only(self):
        old_scan = Scan(id=1, status="complete", started_at=datetime.now(timezone.utc) - timedelta(hours=2))
        new_scan = Scan(id=2, status="complete", started_at=datetime.now(timezone.utc))
        old_dev = Device(id=1, mac="00:11:22:33:44:55", vendor="Wyze", label="Old Camera", is_known=False)
        new_dev = Device(id=2, mac="00:11:22:33:44:66", vendor="Dell", label="New Host", is_known=False)
        old_sd = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.10",
            hostname="old-cam", open_ports="[445]",
            services_json='[{"port":445,"service":"microsoft-ds"}]',
            cves_json='[{"cve":"CVE-2017-0144","risk":"critical","title":"SMB RCE","port":445,"service":"microsoft-ds","recommendation":"Patch SMB"}]',
        )
        new_sd = ScanDevice(
            id=2, scan_id=2, device_id=2, ip="192.168.1.11",
            hostname="new-host", open_ports="[9999]",
            services_json='[{"port":9999,"service":"unknown"}]',
            cves_json='[]',
        )
        self.db.add_all([old_scan, new_scan, old_dev, new_dev, old_sd, new_sd])
        self.db.commit()

        response = self.client.get("/api/security/least-resistance")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["scan"]["id"], 2)
        self.assertEqual(len(data["hosts"]), 1)
        self.assertEqual(data["hosts"][0]["ip"], "192.168.1.11")

    def test_least_resistance_endpoint_dedupes_and_sorts_hosts(self):
        scan = Scan(id=1, status="complete")
        critical_dev = Device(id=1, mac="00:11:22:33:44:55", vendor="Dell", label="Critical Host", is_known=False)
        quiet_dev = Device(id=2, mac="00:11:22:33:44:66", vendor="Generic", label="Quiet Host", is_known=False)
        critical_sd = ScanDevice(
            id=1, scan_id=1, device_id=1, ip="192.168.1.20",
            hostname="critical-host", open_ports="[445]",
            services_json='[{"port":445,"service":"microsoft-ds"}]',
            cves_json='[{"cve":"CVE-2017-0144","risk":"critical","title":"SMB RCE","port":445,"service":"microsoft-ds","recommendation":"Patch SMB"}]',
        )
        quiet_sd = ScanDevice(
            id=2, scan_id=1, device_id=2, ip="192.168.1.21",
            hostname="quiet-host", open_ports="[9999]",
            services_json='[{"port":9999,"service":"unknown"}]',
            cves_json='[]',
        )
        self.db.add_all([scan, critical_dev, quiet_dev, critical_sd, quiet_sd])
        self.db.commit()

        response = self.client.get("/api/security/least-resistance")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual([host["ip"] for host in data["hosts"]], ["192.168.1.20", "192.168.1.21"])
        self.assertEqual(len(data["hosts"][0]["mapped_cves"]), 1)
        self.assertEqual(data["hosts"][0]["mapped_cves"][0]["cve"], "CVE-2017-0144")
        self.assertEqual(data["hosts"][1]["least_resistance_path"]["steps"][0]["title"], "Secure Baseline Check")

    def test_autoheal_status_includes_playbook_and_redacts_secrets(self):
        import monitoring.autoheal as ah

        original_state = dict(ah._STATE)
        now = datetime.now(timezone.utc)
        try:
            self.db.add_all([
                Setting(key="autoheal_enabled", value="true"),
                Setting(key="autoheal_dry_run", value="false"),
                Setting(key="autoheal_reboot_method", value="tasmota"),
                Setting(key="autoheal_router_host", value="192.168.1.1"),
                Setting(key="autoheal_router_user", value="admin"),
                Setting(key="autoheal_router_pass", value="super-secret"),
                Setting(key="autoheal_router_ssl", value="false"),
                Setting(key="autoheal_cooldown_min", value="10"),
                Setting(key="autoheal_max_reboots_per_day", value="1"),
                Setting(key="autoheal_max_reboots_per_outage", value="1"),
                Setting(key="autoheal_smartplug_method", value="none"),
                Setting(key="autoheal_smartplug_pass", value="plug-secret"),
            ])
            self.db.add(ActivityLog(
                category="autoheal",
                event=ah.EV_DRYRUN,
                level="action",
                summary="DRY-RUN: would reboot.",
                detail=json.dumps({"gateway_up": False}),
                created_at=now - timedelta(minutes=2),
            ))
            self.db.commit()

            ah._STATE.update({
                "offline_since": now - timedelta(minutes=12),
                "consecutive_offline": 4,
                "rebooted_this_outage": True,
                "gave_up": False,
                "outage_announced": True,
                "last_probe": {"gateway_up": False},
            })

            response = self.client.get("/api/autoheal")
            self.assertEqual(response.status_code, 200)
            data = response.json()

            self.assertIn("config", data)
            self.assertNotIn("router_pass", data["config"])
            self.assertNotIn("smartplug_pass", data["config"])

            self.assertIn("state", data)
            self.assertTrue(data["state"]["offline"])
            self.assertEqual(data["state"]["consecutive_offline"], 4)
            self.assertTrue(data["state"]["rebooted_this_outage"])

            playbook = data["playbook"]
            self.assertEqual(playbook["proposed_action"], "Power-Cycle via Tasmota Plug")
            self.assertTrue(playbook["is_offline"])
            self.assertIn("router/gateway is not answering on the LAN either", playbook["diagnosis"])
            self.assertEqual(
                [check["name"] for check in playbook["safety_checks"]],
                ["Daily Reboot Cap", "Cooldown Period", "LAN Gateway Ping", "Guardian Armed Status"],
            )
            self.assertFalse(playbook["safety_checks"][0]["passed"])
            self.assertEqual(playbook["safety_checks"][0]["detail"], "1 of 1 used")
            self.assertFalse(playbook["safety_checks"][1]["passed"])
            self.assertIn("remaining", playbook["safety_checks"][1]["detail"])
            self.assertFalse(playbook["safety_checks"][2]["passed"])
            self.assertTrue(playbook["safety_checks"][3]["passed"])
        finally:
            ah._STATE.clear()
            ah._STATE.update(original_state)

    def test_autoheal_status_unknown_method_and_zero_daily_cap(self):
        import monitoring.autoheal as ah

        original_state = dict(ah._STATE)
        try:
            self.db.add_all([
                Setting(key="autoheal_enabled", value="false"),
                Setting(key="autoheal_reboot_method", value="weirdbox"),
                Setting(key="autoheal_max_reboots_per_day", value="0"),
                Setting(key="autoheal_router_port", value="abc"),
            ])
            self.db.commit()

            ah._reset_state()
            ah._STATE["last_probe"] = None

            response = self.client.get("/api/autoheal")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            playbook = data["playbook"]

            self.assertEqual(playbook["proposed_action"], "Reboot via weirdbox")
            self.assertEqual(playbook["diagnosis"], "All systems healthy. No active outages or self-healing actions required at this time.")
            self.assertTrue(playbook["safety_checks"][0]["passed"])
            self.assertEqual(playbook["safety_checks"][0]["detail"], "No limit set")
            self.assertTrue(playbook["safety_checks"][1]["passed"])
            self.assertEqual(playbook["safety_checks"][1]["detail"], "Ready")
            self.assertTrue(playbook["safety_checks"][2]["passed"])
            self.assertEqual(playbook["safety_checks"][2]["detail"], "Gateway (192.168.1.1) responding")
            self.assertFalse(playbook["safety_checks"][3]["passed"])
        finally:
            ah._STATE.clear()
            ah._STATE.update(original_state)

    def test_autoheal_status_ai_enabled_variations(self):
        import monitoring.autoheal as ah

        original_state = dict(ah._STATE)
        try:
            # Case 1: ai_enabled setting is missing (not added to db)
            ah._reset_state()
            ah._STATE["last_probe"] = None
            response = self.client.get("/api/autoheal")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 2: ai_enabled is "true"
            self.db.add(Setting(key="ai_enabled", value="true"))
            self.db.commit()
            response = self.client.get("/api/autoheal")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertTrue(data["playbook"]["ai_enabled"])

            # Case 3: ai_enabled is "false"
            setting = self.db.query(Setting).filter(Setting.key == "ai_enabled").first()
            setting.value = "false"
            self.db.commit()
            response = self.client.get("/api/autoheal")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 4: ai_enabled is malformed "yes"
            setting.value = "yes"
            self.db.commit()
            response = self.client.get("/api/autoheal")
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 5: ai_enabled is malformed "1"
            setting.value = "1"
            self.db.commit()
            response = self.client.get("/api/autoheal")
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 6: ai_enabled is empty string
            setting.value = ""
            self.db.commit()
            response = self.client.get("/api/autoheal")
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 7: ai_enabled is extremely large string to test boundary/safety
            setting.value = "true" * 1000
            self.db.commit()
            response = self.client.get("/api/autoheal")
            data = response.json()
            self.assertFalse(data["playbook"]["ai_enabled"])

            # Case 8: DB exception raised during query (concurrency or error test)
            mock_db = MagicMock()
            mock_db.query.side_effect = Exception("DB connection timeout")
            with self.assertRaises(Exception) as ctx:
                ah.get_playbook(mock_db)
            self.assertEqual(str(ctx.exception), "DB connection timeout")

        finally:
            ah._STATE.clear()
            ah._STATE.update(original_state)
            # Cleanup settings
            self.db.query(Setting).filter(Setting.key == "ai_enabled").delete()
            self.db.commit()

    def test_uptime_guardian_component_renders_action_card_contract(self):
        from pathlib import Path

        source = Path(__file__).resolve().parents[1] / "frontend" / "src" / "components" / "sections" / "UptimeGuardian.tsx"
        text = source.read_text(encoding="utf-8")
        # Verify conditional expressions pinning the AI vs non-AI feature UI updates
        self.assertIn('data.playbook.ai_enabled ? "AI-Driven Self-Healing Playbook" : "Self-Healing Playbook"', text)
        self.assertIn('data.playbook.ai_enabled ? "AI Diagnosis & Playbook" : "Diagnosis & Playbook"', text)
        self.assertIn('data?.playbook?.ai_enabled ? "AI-Narrated Self-Healing Timeline" : "Self-Healing Timeline"', text)
        self.assertIn('data?.playbook?.ai_enabled ? "AI Guardian Report" : "Guardian Report"', text)

        self.assertIn("Proposed Healing Action", text)
        self.assertIn("Safety Check Pre-requisites", text)
        self.assertIn("data?.playbook", text)
        self.assertIn("data.playbook.safety_checks?.map", text)
        self.assertIn("Execute Action", text)
        self.assertNotIn("Internet outage detected", text)

    def test_attack_graph_option_uses_echarts_graph_data_array(self):
        from pathlib import Path
        source = Path(__file__).resolve().parents[1] / "frontend" / "src" / "components" / "sections" / "SecurityLab.tsx"
        text = source.read_text(encoding="utf-8")
        self.assertIn("data: nodes", text, "ECharts graph series must use the 'data' property for node records")
        self.assertNotIn("nodes,", text, "The graph series should not rely on a nonstandard 'nodes' option")

    def test_security_lab_renders_least_resistance_tab(self):
        from pathlib import Path
        source = Path(__file__).resolve().parents[1] / "frontend" / "src" / "components" / "sections" / "SecurityLab.tsx"
        text = source.read_text(encoding="utf-8")
        self.assertIn("Least Resistance", text)
        self.assertIn("LeastResistancePanel", text)
        self.assertIn("tab === 'least_resistance'", text)
        self.assertIn("queryKey: ['least-resistance']", text)
        self.assertIn("/api/security/least-resistance", text)

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

    def test_ghost_detection_flags_rogue_ap_like_device(self):
        """Test device payloads expose ghost detection for obvious rogue AP fingerprints."""
        scan = Scan(id=60, status="complete", started_at=datetime.now(timezone.utc))
        ghost = Device(
            id=60,
            mac="aa:bb:cc:dd:ee:ff",
            vendor="Ubiquiti",
            hostname="mesh-router",
            label="Rogue AP",
            is_known=False,
        )
        scan_device = ScanDevice(
            id=60,
            scan_id=60,
            device_id=60,
            ip="192.168.1.250",
            hostname="rogue-ap",
            open_ports="[80, 443, 8080]",
        )
        self.db.add_all([scan, ghost, scan_device])
        self.db.commit()

        response = self.client.get("/api/devices/all?current_only=true")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        ghost_detection = data[0]["ghost_detection"]
        self.assertIsNotNone(ghost_detection)
        self.assertTrue(ghost_detection["is_ghost"])
        self.assertEqual(ghost_detection["kind"], "rogue_ap")
        self.assertGreaterEqual(ghost_detection["score"], 3)
        self.assertTrue(any("AP-like" in reason or "Management-style" in reason for reason in ghost_detection["reasons"]))

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

    def test_get_devices_at_scan_not_found(self):
        """Test GET /api/devices/at-scan/{scan_id} with a non-existent scan ID."""
        response = self.client.get("/api/devices/at-scan/999")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Scan not found")

    def test_get_devices_at_scan_incomplete(self):
        """Test GET /api/devices/at-scan/{scan_id} with an incomplete scan."""
        scan = Scan(id=10, status="running", started_at=datetime.now(timezone.utc))
        self.db.add(scan)
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/10")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "Scan not found")

    def test_get_devices_at_scan_empty(self):
        """Test GET /api/devices/at-scan/{scan_id} when scan has no device records."""
        scan = Scan(id=20, status="complete", started_at=datetime.now(timezone.utc))
        self.db.add(scan)
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/20")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_get_devices_at_scan_success(self):
        """Test GET /api/devices/at-scan/{scan_id} with a valid completed scan and devices."""
        scan = Scan(id=30, status="complete", started_at=datetime.now(timezone.utc))
        device = Device(id=100, mac="00:aa:bb:cc:dd:ee", vendor="Netgear", label="My Switch", is_known=True, os_guess="Linux")
        scan_device = ScanDevice(
            id=200,
            scan_id=30,
            device_id=100,
            ip="192.168.1.15",
            hostname="switch-host",
            open_ports="[80, 443]",
            services_json='[{"port": 80}]',
            cves_json='[{"cve": "CVE-TEST-1", "risk": "low"}, {"cve": "CVE-TEST-2", "risk": "critical"}]'
        )
        self.db.add_all([scan, device, scan_device])
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/30")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        
        dev_data = data[0]
        self.assertEqual(dev_data["id"], 100)
        self.assertEqual(dev_data["mac"], "00:aa:bb:cc:dd:ee")
        self.assertEqual(dev_data["vendor"], "Netgear")
        self.assertEqual(dev_data["hostname"], "switch-host")
        self.assertEqual(dev_data["label"], "My Switch")
        self.assertEqual(dev_data["is_known"], True)
        self.assertEqual(dev_data["latest_ip"], "192.168.1.15")
        self.assertEqual(dev_data["open_ports"], [80, 443])
        self.assertEqual(dev_data["vulnerability_count"], 2)
        self.assertEqual(dev_data["max_cve_risk"], "critical")
        self.assertEqual(dev_data["os_guess"], "Linux")

    def test_get_devices_at_scan_fallback_null_values(self):
        """Test fallback handling when fields in Device or ScanDevice are null."""
        scan = Scan(id=40, status="complete", started_at=datetime.now(timezone.utc))
        device = Device(id=101, mac=None, vendor=None, label=None, is_known=False, os_guess=None)
        scan_device = ScanDevice(
            id=201,
            scan_id=40,
            device_id=101,
            ip="192.168.1.16",
            hostname=None,
            open_ports=None,
            services_json=None,
            cves_json=None
        )
        self.db.add_all([scan, device, scan_device])
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/40")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        
        dev_data = data[0]
        self.assertEqual(dev_data["mac"], "unknown")
        self.assertEqual(dev_data["vendor"], "")
        self.assertEqual(dev_data["hostname"], "")
        self.assertEqual(dev_data["label"], "")
        self.assertEqual(dev_data["os_guess"], "")
        self.assertEqual(dev_data["open_ports"], [])
        self.assertEqual(dev_data["vulnerability_count"], 0)
        self.assertIsNone(dev_data["max_cve_risk"])

    def test_get_devices_at_scan_freshest_device(self):
        """Test that only the freshest ScanDevice row per device is returned when multiple exist."""
        scan = Scan(id=50, status="complete", started_at=datetime.now(timezone.utc))
        device = Device(id=102, mac="00:11:22:33:44:55", vendor="Apple")
        # Add two ScanDevices for device 102 in the same scan/window.
        sd_old = ScanDevice(
            id=202,
            scan_id=50,
            device_id=102,
            ip="192.168.1.100",
            hostname="old-name",
            open_ports="[80]"
        )
        sd_new = ScanDevice(
            id=203,
            scan_id=50,
            device_id=102,
            ip="192.168.1.101",
            hostname="new-name",
            open_ports="[80, 443]"
        )
        self.db.add_all([scan, device, sd_old, sd_new])
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/50")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["latest_ip"], "192.168.1.101")
        self.assertEqual(data[0]["hostname"], "new-name")
        self.assertEqual(data[0]["open_ports"], [80, 443])

    def test_get_devices_at_scan_malformed_cves(self):
        """Test vulnerability parsing edge cases (missing risk, invalid types, or mixed risks)."""
        scan = Scan(id=60, status="complete", started_at=datetime.now(timezone.utc))
        device = Device(id=103, mac="00:11:22:33:44:aa")
        scan_device = ScanDevice(
            id=204,
            scan_id=60,
            device_id=103,
            ip="192.168.1.102",
            services_json='[{"port": 22}]',
            cves_json='[{"cve": "CVE-1"}, {"cve": "CVE-2", "risk": 999}, {"cve": "CVE-3", "risk": "low"}, {"cve": "CVE-4", "risk": "high"}]'
        )
        self.db.add_all([scan, device, scan_device])
        self.db.commit()

        response = self.client.get("/api/devices/at-scan/60")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["vulnerability_count"], 4)
        self.assertEqual(data[0]["max_cve_risk"], "high")

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

