import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from app.db import init_db, create_demo_account, list_demo_accounts, get_demo_account, record_demo_cleanup
from app.session_intelligence import (
    probe_session, create_demo_account as si_create, run_demo_cleanup,
    _detect_os_from_output, _detect_privilege, _detect_user, _extract_interfaces,
)
from app.routes import create_app


LINUX_PROFILE_OUTPUT = """Linux webserver 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 x86_64 GNU/Linux
uid=0(root) gid=0(root) groups=0(root)
root
1: lo: <LOOPBACK> mtu 65536 qdisc noqueue
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST> mtu 1500 qdisc pfifo_fast
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"""

WINDOWS_PROFILE_OUTPUT = """Microsoft Windows [Version 10.0.19045.4842]
User Name:  DESKTOP\\Administrator
NT AUTHORITY\\SYSTEM
IPv4 Address. . . . . : 192.168.1.200"""


class OSDetectionTest(unittest.TestCase):
    def test_linux_detected_from_uname_output(self):
        plat, conf = _detect_os_from_output(LINUX_PROFILE_OUTPUT)
        self.assertEqual(plat, "linux")
        self.assertEqual(conf, "high")

    def test_windows_detected_from_systeminfo_output(self):
        plat, conf = _detect_os_from_output(WINDOWS_PROFILE_OUTPUT)
        self.assertEqual(plat, "windows")
        self.assertEqual(conf, "high")

    def test_unknown_os_when_no_identifiable_strings(self):
        plat, conf = _detect_os_from_output("no information available")
        self.assertEqual(plat, "unknown")

    def test_linux_root_privilege_detected_from_uid_zero(self):
        priv = _detect_privilege(LINUX_PROFILE_OUTPUT, "linux")
        self.assertEqual(priv, "root")

    def test_linux_user_privilege_when_not_root(self):
        output = "uid=1001(alice) gid=1001(alice) groups=1001(alice)\nalice"
        priv = _detect_privilege(output, "linux")
        self.assertEqual(priv, "user")

    def test_windows_administrator_detected(self):
        priv = _detect_privilege(WINDOWS_PROFILE_OUTPUT, "windows")
        self.assertEqual(priv, "administrator")

    def test_user_extracted_from_linux_uid_line(self):
        user = _detect_user(LINUX_PROFILE_OUTPUT, "linux")
        self.assertEqual(user, "root")

    def test_interfaces_extracted_from_ip_addr(self):
        ifaces = _extract_interfaces(LINUX_PROFILE_OUTPUT, "linux")
        ips = {i["ip"] for i in ifaces}
        self.assertIn("127.0.0.1", ips)
        self.assertIn("192.168.1.100", ips)


class SessionProbeTest(unittest.TestCase):
    def test_probe_returns_structured_profile_on_success(self):
        def mock_interact(c, s, cmd):
            return {"output": LINUX_PROFILE_OUTPUT}
        profile = probe_session(mock_interact, "ctrl1", "2", "linux")
        self.assertTrue(profile["ok"])
        self.assertEqual(profile["os"], "linux")
        self.assertEqual(profile["privilege"], "root")
        self.assertEqual(profile["user"], "root")
        self.assertGreater(len(profile["interfaces"]), 0)

    def test_probe_returns_safe_error_on_interact_failure(self):
        def bad_interact(c, s, cmd):
            raise Exception("session closed")
        profile = probe_session(bad_interact, "ctrl1", "2")
        self.assertFalse(profile["ok"])
        self.assertIn("error", profile)
        self.assertEqual(profile["os"], "unknown")


class DemoAccountCreationTest(unittest.TestCase):
    def _mock_interact_creates_successfully(self, c, s, cmd):
        return {"output": "uid=2001(asep_demo_1234567890) gid=2001(asep_demo_1234567890)"}

    def test_dry_run_returns_commands_without_executing(self):
        called = []
        def mock_interact(c, s, cmd): called.append(cmd); return {"output": ""}
        r = si_create(mock_interact, "c", "1", "linux", "root", dry_run=True)
        self.assertTrue(r["ok"])
        self.assertTrue(r["dry_run"])
        self.assertTrue(r["username"].startswith("asep_demo_"))
        self.assertEqual(called, [])  # dry_run means NO commands sent

    def test_unknown_os_is_blocked(self):
        r = si_create(MagicMock(), "c", "1", "unknown", "root", dry_run=False)
        self.assertFalse(r["ok"])
        self.assertIn("not supported", r["reason"])

    def test_darwin_os_is_blocked(self):
        r = si_create(MagicMock(), "c", "1", "darwin", "root", dry_run=False)
        self.assertFalse(r["ok"])

    def test_insufficient_privilege_is_blocked(self):
        r = si_create(MagicMock(), "c", "1", "linux", "user", dry_run=False)
        self.assertFalse(r["ok"])
        self.assertIn("insufficient", r["reason"].lower())

    def test_windows_user_privilege_is_blocked(self):
        r = si_create(MagicMock(), "c", "1", "windows", "user", dry_run=False)
        self.assertFalse(r["ok"])

    def test_account_username_always_starts_with_asep_demo(self):
        def mock_interact(c, s, cmd):
            return {"output": "uid=2001(asep_demo_1234567890)"}
        r = si_create(mock_interact, "c", "1", "linux", "root", dry_run=True)
        self.assertTrue(r["username"].startswith("asep_demo_"))

    def test_non_asep_prefix_rejected_in_cleanup(self):
        r = run_demo_cleanup(MagicMock(), "c", "1", "linux", "existing_user")
        self.assertFalse(r["ok"])
        self.assertIn("not match", r["reason"])


class DemoAccountPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {"root": self.tmp.name, "data_root": self.tmp.name}
        init_db(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_demo_account_persists_in_db(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_test", "root", "created", "validated")
        row = get_demo_account(self.cfg, aid)
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "asep_demo_test")
        self.assertEqual(row["cleanup_state"], "PENDING_OPERATOR_CONFIRMATION")

    def test_demo_account_not_in_active_list_after_cleanup_verified(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_test", "root", "ok", "ok")
        record_demo_cleanup(self.cfg, aid, "CLEANUP_VERIFIED", "removed", "operator")
        active = list_demo_accounts(self.cfg, include_cleaned=False)
        all_accounts = list_demo_accounts(self.cfg, include_cleaned=True)
        self.assertEqual(len(active), 0)
        self.assertEqual(len(all_accounts), 1)

    def test_cleanup_state_starts_as_pending_never_auto_set(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_abc", "root", "ok", "ok")
        # Simulate restart (re-read from DB): state must still be PENDING
        row = get_demo_account(self.cfg, aid)
        self.assertEqual(row["cleanup_state"], "PENDING_OPERATOR_CONFIRMATION")
        # No magic auto-cleanup happened
        self.assertIsNone(row["cleanup_at"])

    def test_record_cleanup_only_updates_cleanup_fields(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_xyz", "root", "ok", "ok")
        record_demo_cleanup(self.cfg, aid, "CLEANUP_FAILED", "account not found after retry", "operator")
        row = get_demo_account(self.cfg, aid)
        self.assertEqual(row["cleanup_state"], "CLEANUP_FAILED")
        self.assertEqual(row["username"], "asep_demo_xyz")  # not changed


class DemoAccountAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name, ".env").write_text("", encoding="utf-8")
        self.cfg = {"root": self.tmp.name, "data_root": self.tmp.name,
                    "scope": {"scope": {"networks": [], "hosts": []}, "restrictions": {}},
                    "llm_mode": "auto", "openai_api_key": "", "local_enabled": False,
                    "claude_code_enabled": False, "internet_check_url": "https://dns.google",
                    "internet_check_interval": 60, "internet_check_timeout": 5,
                    "llm_health_check_interval": 60, "deep_scan_concurrency": 3,
                    "deep_scan_host_timeout": 480}
        init_db(self.cfg)
        self.app = create_app(self.cfg)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_demo_accounts_returns_empty_initially(self):
        r = self.client.get("/api/session/demo-account/list")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["accounts"], [])

    def test_cleanup_requires_confirm_flag(self):
        # Seed a demo account directly in DB
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_test", "root", "ok", "ok")
        # Without confirm
        r = self.client.post(f"/api/session/demo-account/{aid}/cleanup",
                             json={}, content_type="application/json")
        self.assertEqual(r.status_code, 400)
        body = r.get_json()
        self.assertIn("confirm", body["error"].lower())

    def test_cleanup_without_confirm_does_not_change_state(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_test2", "root", "ok", "ok")
        self.client.post(f"/api/session/demo-account/{aid}/cleanup",
                         json={}, content_type="application/json")
        row = get_demo_account(self.cfg, aid)
        self.assertEqual(row["cleanup_state"], "PENDING_OPERATOR_CONFIRMATION")

    def test_demo_account_status_endpoint(self):
        aid = create_demo_account(self.cfg, "10.0.0.1", "c1", "2", "linux", "high",
                                   "asep_demo_status", "root", "ok", "ok")
        r = self.client.get(f"/api/session/demo-account/{aid}/status")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["account"]["username"], "asep_demo_status")


if __name__ == "__main__":
    unittest.main()
