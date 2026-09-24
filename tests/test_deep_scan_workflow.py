import unittest
from pathlib import Path


class DeepScanWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.routes = (self.root / "app" / "routes.py").read_text(encoding="utf-8")
        self.js = (self.root / "static" / "app.js").read_text(encoding="utf-8")
        self.html = (self.root / "templates" / "index.html").read_text(encoding="utf-8")

    def test_comprehensive_profile_scans_tcp_all_ports_only(self):
        nmap = (self.root / "app" / "nmap_executor.py").read_text(encoding="utf-8")
        for token in ['"deep_full"', '"-sT"', '"-p-"', '"-sV"', '"--version-all"', '"--allports"']:
            self.assertIn(token, nmap)

    def test_dashboard_auto_awareness_function_is_defined_and_invoked(self):
        self.assertIn("def _ensure_auto_awareness", self.routes)
        self.assertIn("_ensure_auto_awareness()", self.routes)
        self.assertIn("interval = 30.0", self.routes)

    def test_dashboard_automatically_starts_comprehensive_batch(self):
        self.assertIn("def _maybe_auto_deep_scan", self.routes)
        self.assertIn('_maybe_auto_deep_scan(result.get("network", {}).get("network", ""), active)', self.routes)
        self.assertIn('reason="automatic"', self.routes)

    def test_new_hosts_are_not_rescanned_every_awareness_cycle(self):
        self.assertIn('"scanned_hosts"', self.routes)
        self.assertIn('t not in scanned', self.routes)

    def test_dashboard_refreshes_after_scan_completion(self):
        self.assertIn("lastDeepScanFinishedAt", self.js)
        self.assertIn("loadDashboard()", self.js)

    def test_manual_control_is_rescan_not_initial_trigger(self):
        self.assertIn("RESCAN ALL SERVICES", self.html)

class DeepScanPersistenceUXTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.routes = (self.root / "app" / "routes.py").read_text(encoding="utf-8")
        self.ux = (self.root / "app" / "ux.py").read_text(encoding="utf-8")
        self.nmap = (self.root / "app" / "nmap_executor.py").read_text(encoding="utf-8")
        self.js = (self.root / "static" / "app.js").read_text(encoding="utf-8")
        self.css = (self.root / "static" / "app.css").read_text(encoding="utf-8")

    def test_discovery_preserves_deep_scan_metadata(self):
        self.assertIn("prior_md = (prior or {}).get(\"metadata\") or {}", self.routes)
        self.assertIn("discovery_md = {", self.routes)
        self.assertIn('"deep_scan"', self.routes)

    def test_completed_service_scan_is_persistent_source_of_truth(self):
        self.assertIn("latest_service_scan(cfg, address)", self.ux)
        self.assertIn('latest_scan.get("profile")', self.ux)
        self.assertIn('latest_scan.get("status")', self.ux)

    def test_deep_scan_has_per_host_timeout_and_progress_state(self):
        for token in ['"--host-timeout", "5m"', '"--max-retries", "3"', '"-T4"']:
            self.assertIn(token, self.nmap)
        for token in ['"current_started_at"', '"last_progress_at"', '"elapsed_sec"']:
            self.assertIn(token, self.routes)

    def test_failed_host_is_not_retried_immediately_by_auto_discovery(self):
        self.assertIn('failed_at.get(t, 0)', self.routes)
        self.assertIn('>= 1800', self.routes)
        self.assertIn('reason="automatic"', self.routes)

    def test_dashboard_and_target_inventory_show_persistent_green_markers(self):
        self.assertIn('DEEP SCAN ✓', self.js)
        self.assertIn('msf-action', self.js)
        self.assertIn('.deep-scan-badge', self.css)
        self.assertIn('.msf-action', self.css)
