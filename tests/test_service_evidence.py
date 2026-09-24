import json
import tempfile
import unittest

from app.db import init_db, add_evidence, list_evidence, upsert_target
from app.routes import create_app


class ServiceEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "root": self.tmp.name,
            "data_root": self.tmp.name,
            "scope": {"scope": {"networks": ["192.168.1.0/24"], "hosts": []}, "restrictions": {}},
        }
        init_db(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_evidence_can_return_raw_data_for_focused_consumers(self):
        add_evidence(self.cfg, "service_scan", "192.168.1.12", "2 services", json.dumps({"ports": [{"port": "22"}]}))
        self.assertNotIn("data", list_evidence(self.cfg)[0])
        rows = list_evidence(self.cfg, include_data=True)
        self.assertEqual(json.loads(rows[0]["data"])["ports"][0]["port"], "22")

    def test_target_detail_reads_service_scan_payload(self):
        upsert_target(self.cfg, {
            "address": "192.168.1.12", "name": "host", "role": "unknown", "state": "up",
            "scope_status": "IN-SCOPE", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Example",
            "interface": "eth0", "source": "test", "metadata": {"hostname": "host"},
        })
        payload = {"target": "192.168.1.12", "ports": [
            {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.2p1", "detection": "Nmap -sV"}
        ]}
        add_evidence(self.cfg, "service_scan", "192.168.1.12", "1 service", json.dumps(payload))
        app = create_app(self.cfg)
        client = app.test_client()
        r = client.get('/api/v2/target/192.168.1.12')
        self.assertEqual(r.status_code, 200)
        target = r.get_json()["target"]
        self.assertEqual(target["service_count"], 1)
        self.assertEqual(target["services"][0]["service"], "ssh")
        self.assertEqual(target["services"][0]["version"], "9.2p1")


if __name__ == '__main__':
    unittest.main()


    def test_create_app_accepts_string_root(self):
        # Regression: config roots may be strings; route creation must convert
        # them to Path before joining the templates directory.
        import tempfile
        from app.routes import create_app

        with tempfile.TemporaryDirectory() as td:
            cfg = dict(self.cfg)
            cfg["root"] = td
            app = create_app(cfg)
            self.assertIsNotNone(app)


    def test_deep_full_profile_is_comprehensive(self):
        from app.nmap_executor import PROFILES
        profile = PROFILES["deep_full"]
        self.assertIn("-p-", profile)
        self.assertNotIn("-sU", profile)
        self.assertIn("-sV", profile)
        self.assertIn("--version-all", profile)
        self.assertIn("--allports", profile)
