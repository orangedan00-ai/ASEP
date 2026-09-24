import json
import tempfile
import unittest
from pathlib import Path

from app.db import init_db
from app.routes import create_app


class LlmModeEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name, ".env").write_text("OPENAI_API_KEY=sk-should-not-move\nASEP_LLM_MODE=auto\n", encoding="utf-8")
        self.cfg = {
            "root": self.tmp.name,
            "data_root": self.tmp.name,
            "scope": {"scope": {"networks": [], "hosts": []}, "restrictions": {}},
            "llm_mode": "auto",
            "openai_api_key": "",
            "local_enabled": False,
            "claude_code_enabled": False,
        }
        init_db(self.cfg)
        self.app = create_app(self.cfg)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_mode_switches_immediately_and_persists(self):
        r = self.client.post("/api/settings/llm-mode", json={"mode": "local"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["requested_mode"], "local")
        self.assertTrue(body["persisted_to_env"])
        # Immediate effect: the shared cfg dict must reflect the change right away.
        self.assertEqual(self.cfg["llm_mode"], "local")
        # Persisted: .env on disk must carry the new value, untouched secret preserved.
        env_content = Path(self.tmp.name, ".env").read_text(encoding="utf-8")
        self.assertIn("ASEP_LLM_MODE=local", env_content)
        self.assertIn("OPENAI_API_KEY=sk-should-not-move", env_content)

    def test_invalid_mode_is_rejected_and_does_not_change_cfg(self):
        r = self.client.post("/api/settings/llm-mode", json={"mode": "quantum"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.cfg["llm_mode"], "auto")  # unchanged

    def test_status_endpoint_reflects_the_switch(self):
        self.client.post("/api/settings/llm-mode", json={"mode": "claude_code"})
        r = self.client.get("/api/intelligence/status")
        body = r.get_json()
        self.assertEqual(body["requested_mode"], "claude_code")
        self.assertIn("claude_code", body)


if __name__ == "__main__":
    unittest.main()
