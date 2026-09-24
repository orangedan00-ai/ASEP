import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.db import add_evidence, init_db, list_targets, connect, upsert_target
from app.environment_state import prepare_environment_state


class EnvironmentStateTest(unittest.TestCase):
    def _cfg(self, root):
        return {"root": Path(root), "data_root": Path(root)}

    def _identity(self, boot_id, network="192.168.1.0/24", interface="eth0", local_ip="192.168.1.23", gateway="192.168.1.1"):
        return {
            "boot_id": boot_id,
            "network": network,
            "interface": interface,
            "kind": "ethernet",
            "local_ip": local_ip,
            "gateway": gateway,
        }

    def test_restart_clears_network_inventory_but_keeps_audit(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td)
            init_db(cfg)
            upsert_target(cfg, {"address": "192.168.1.10", "metadata": {"ports": [{"port": "22"}]}})
            add_evidence(cfg, "deep_service_scan", "192.168.1.10", "old", json.dumps({"port": 22}))
            con = connect(cfg)
            con.execute("INSERT INTO audit(created_at,action,target,status,details) VALUES(?,?,?,?,?)", ("now", "test", "old", "OK", "keep"))
            con.commit(); con.close()

            with patch("app.environment_state.current_environment_identity", return_value=self._identity("boot-new")), \
                 patch("app.environment_state._load_state", return_value=self._identity("boot-old")), \
                 patch("app.environment_state._write_state"):
                result = prepare_environment_state(cfg)

            self.assertTrue(result["changed"])
            self.assertEqual(result["reason"], "reboot")
            self.assertEqual(list_targets(cfg), [])
            con = connect(cfg)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM discovery_runs").fetchone()[0], 0)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM audit").fetchone()[0], 1)
            con.close()

    def test_dhcp_ip_change_triggers_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td)
            init_db(cfg)
            upsert_target(cfg, {"address": "192.168.1.10", "metadata": {}})
            previous = self._identity("same-boot", local_ip="192.168.1.23")
            current = self._identity("same-boot", local_ip="10.0.0.25", network="10.0.0.0/24", gateway="10.0.0.1")
            with patch("app.environment_state.current_environment_identity", return_value=current), \
                 patch("app.environment_state._load_state", return_value=previous), \
                 patch("app.environment_state._write_state"):
                result = prepare_environment_state(cfg)
            self.assertTrue(result["changed"])
            self.assertEqual(result["reason"], "network-change")
            self.assertEqual(list_targets(cfg), [])

    def test_unchanged_environment_keeps_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._cfg(td)
            init_db(cfg)
            upsert_target(cfg, {"address": "192.168.1.10", "metadata": {}})
            identity = self._identity("same-boot")
            with patch("app.environment_state.current_environment_identity", return_value=identity), \
                 patch("app.environment_state._load_state", return_value=identity), \
                 patch("app.environment_state._write_state"):
                result = prepare_environment_state(cfg)
            self.assertFalse(result["changed"])
            self.assertEqual(list_targets(cfg)[0]["address"], "192.168.1.10")


if __name__ == "__main__":
    unittest.main()
