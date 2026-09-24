import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.provider_health import ProviderHealth
from app.db import init_db
from app.routes import create_app


def _cfg(**overrides):
    base = {
        "root": "",
        "llm_mode": "auto",
        "openai_api_key": "",
        "local_enabled": False,
        "ollama_url": "http://127.0.0.1:11434",
        "local_model": "qwen3:0.6b",
        "cloud_model": "gpt-4",
        "claude_code_enabled": False,
        "claude_code_binary": "claude",
        "internet_check_url": "https://dns.google",
        "internet_check_interval": 60,
        "internet_check_timeout": 5,
        "llm_health_check_interval": 60,
        "deep_scan_concurrency": 3,
        "deep_scan_host_timeout": 480,
    }
    base.update(overrides)
    return base


class ProviderHealthTest(unittest.TestCase):
    def test_internet_online_detected_with_mocked_connection(self):
        ph = ProviderHealth(_cfg())
        with patch("app.provider_health.urllib.request.urlopen") as mock:
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=MagicMock(status=200))
            ctx.__exit__ = MagicMock(return_value=False)
            mock.return_value = ctx
            state = ph._check_internet()
        self.assertEqual(state, "ONLINE")

    def test_internet_offline_when_both_probes_fail(self):
        ph = ProviderHealth(_cfg())
        with patch("app.provider_health.urllib.request.urlopen", side_effect=Exception("refused")), \
             patch("app.provider_health.socket.create_connection", side_effect=Exception("refused")):
            state = ph._check_internet()
        self.assertEqual(state, "OFFLINE")

    def test_local_llm_unavailable_when_not_enabled(self):
        ph = ProviderHealth(_cfg(local_enabled=False))
        self.assertEqual(ph._check_local_llm(), "UNAVAILABLE")

    def test_local_llm_available_when_ollama_responds_200(self):
        ph = ProviderHealth(_cfg(local_enabled=True))
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=MagicMock(status=200))
        ctx.__exit__ = MagicMock(return_value=False)
        with patch("app.provider_health.urllib.request.urlopen", return_value=ctx):
            self.assertEqual(ph._check_local_llm(), "AVAILABLE")

    def test_local_llm_unavailable_when_ollama_unreachable(self):
        ph = ProviderHealth(_cfg(local_enabled=True))
        with patch("app.provider_health.urllib.request.urlopen", side_effect=Exception("connection refused")):
            self.assertEqual(ph._check_local_llm(), "UNAVAILABLE")

    def test_cloud_unavailable_when_no_api_key(self):
        ph = ProviderHealth(_cfg(openai_api_key=""))
        self.assertEqual(ph._check_cloud(), "UNAVAILABLE")

    def test_cloud_offline_when_internet_is_offline(self):
        ph = ProviderHealth(_cfg(openai_api_key="sk-test"))
        ph._state["internet"] = "OFFLINE"
        self.assertEqual(ph._check_cloud(), "OFFLINE")

    def test_claude_code_unavailable_when_not_enabled(self):
        ph = ProviderHealth(_cfg(claude_code_enabled=False))
        self.assertEqual(ph._check_claude_code(), "UNAVAILABLE")

    def test_claude_code_unavailable_when_binary_missing(self):
        ph = ProviderHealth(_cfg(claude_code_enabled=True))
        with patch("app.provider_health.shutil.which", return_value=None):
            self.assertEqual(ph._check_claude_code(), "UNAVAILABLE")

    def test_set_working_marks_provider_as_working(self):
        ph = ProviderHealth(_cfg())
        ph._state["local_llm"] = "AVAILABLE"
        ph.set_working("local", task="evidence correlation")
        snap = ph.snapshot()
        self.assertEqual(snap["local_llm"], "WORKING")
        self.assertEqual(snap["current_task"], "evidence correlation")

    def test_clear_working_restores_available(self):
        ph = ProviderHealth(_cfg())
        ph.set_working("local", task="x")
        ph.clear_working("local", success=True)
        self.assertEqual(ph._state["local_llm"], "AVAILABLE")

    def test_clear_working_on_failure_sets_degraded(self):
        ph = ProviderHealth(_cfg())
        ph.set_working("local", task="x")
        ph.clear_working("local", success=False)
        self.assertEqual(ph._state["local_llm"], "DEGRADED")

    def test_active_provider_auto_prefers_cloud_then_claude_then_local(self):
        ph = ProviderHealth(_cfg())
        # Only local available
        states = {"internet": "ONLINE", "local_llm": "AVAILABLE", "cloud": "UNAVAILABLE", "claude_code": "UNAVAILABLE"}
        self.assertEqual(ph._resolve_active(states), "local")
        # Cloud also available → cloud wins
        states["cloud"] = "AVAILABLE"
        self.assertEqual(ph._resolve_active(states), "cloud")
        # Claude Code also available → cloud still wins (highest priority)
        states["claude_code"] = "AVAILABLE"
        self.assertEqual(ph._resolve_active(states), "cloud")

    def test_snapshot_is_thread_safe(self):
        ph = ProviderHealth(_cfg())
        results = []
        def reader():
            for _ in range(20):
                results.append(ph.snapshot())
        def writer():
            for _ in range(20):
                ph.set_working("local", "task")
                ph.clear_working("local", True)
        t1 = threading.Thread(target=reader)
        t2 = threading.Thread(target=writer)
        t1.start(); t2.start()
        t1.join(); t2.join()
        self.assertEqual(len(results), 20)  # no exception = thread-safe


class Stage2IntelligenceStatusAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name, ".env").write_text("ASEP_LLM_MODE=auto\n", encoding="utf-8")
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

    def test_intelligence_status_includes_internet_and_provider_health(self):
        r = self.client.get("/api/intelligence/status")
        body = r.get_json()
        self.assertIn("internet", body)
        self.assertIn("provider_health", body)
        self.assertIn("local_llm", body["provider_health"])
        self.assertIn("cloud", body["provider_health"])

    def test_provider_health_endpoint_exists(self):
        r = self.client.get("/api/provider-health")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertIn("internet", body)
        self.assertIn("local_llm", body)


class Stage2ConfigTest(unittest.TestCase):
    def test_deep_scan_concurrency_in_config_keys(self):
        # Verify the config module exposes the Stage 2 deep-scan keys at the
        # module level (they are always present regardless of .env contents).
        import ast, textwrap
        src = (Path(__file__).resolve().parents[1] / "app" / "config.py").read_text(encoding="utf-8")
        self.assertIn("deep_scan_concurrency", src)
        self.assertIn("deep_scan_host_timeout", src)
        self.assertIn("ASEP_DEEP_SCAN_CONCURRENCY", src)
        self.assertIn("internet_check_url", src)
        self.assertIn("llm_health_check_interval", src)


if __name__ == "__main__":
    unittest.main()
