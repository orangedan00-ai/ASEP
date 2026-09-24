import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.db import init_db
from app.routes import create_app


class SkillsEndpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        Path(self.tmp.name, ".env").write_text("ASEP_LLM_MODE=auto\n", encoding="utf-8")
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

    def test_list_skills_returns_all_75(self):
        r = self.client.get("/api/skills")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(len(body["skills"]), 75)
        ids = {s["id"] for s in body["skills"]}
        self.assertIn("attack_path_intelligence", ids)
        self.assertIn("reporting_intelligence", ids)
        self.assertIn("broad_exploit_discovery_intelligence", ids)

    def test_reason_requires_context(self):
        r = self.client.post("/api/skills/reason", json={})
        self.assertEqual(r.status_code, 400)

    def test_reason_rejects_non_list_skill_ids(self):
        r = self.client.post("/api/skills/reason", json={"context": "x", "skill_ids": "not-a-list"})
        self.assertEqual(r.status_code, 400)

    def test_reason_with_no_llm_configured_returns_none_mode_not_an_error(self):
        r = self.client.post("/api/skills/reason", json={"context": "apache 2.4.49 metasploit check"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["mode"], "none")
        self.assertIn("metasploit_intelligence", body["skill_ids"])

    def test_reason_uses_explicit_skill_ids_when_given(self):
        r = self.client.post("/api/skills/reason", json={"context": "x", "skill_ids": ["wireless_intelligence"]})
        body = r.get_json()
        self.assertEqual(body["skill_ids"], ["wireless_intelligence"])

    def test_reason_logs_evidence(self):
        from app.db import list_evidence
        self.client.post("/api/skills/reason", json={"context": "session shell meterpreter"})
        rows = list_evidence(self.cfg)
        self.assertTrue(any(row["evidence_type"] == "skill_reasoning" for row in rows))


if __name__ == "__main__":
    unittest.main()
