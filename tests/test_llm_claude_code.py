import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.llm import LLMRouter
from app.db import init_db
from app.skill_registry import seed_builtin_skills

ROOT = Path(__file__).resolve().parents[1]


def _cfg(**overrides):
    cfg = {
        "root": ROOT,
        "llm_mode": "claude_code",
        "openai_api_key": "",
        "cloud_model": "gpt-5.6-luna",
        "local_enabled": False,
        "ollama_url": "http://127.0.0.1:11434",
        "local_model": "qwen3:0.6b",
        "claude_code_enabled": True,
        "claude_code_binary": "claude",
        "claude_code_timeout": 30,
        "claude_code_max_turns": 4,
    }
    cfg.update(overrides)
    return cfg


class ClaudeCodeBackendTest(unittest.TestCase):
    def test_binary_not_found_raises_clear_error(self):
        router = LLMRouter(_cfg())
        with patch("app.llm.shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                router.ask_claude_code("test prompt")
        self.assertIn("PATH", str(ctx.exception))

    def test_successful_response_parses_result_field(self):
        router = LLMRouter(_cfg())
        fake_proc = MagicMock()
        fake_proc.returncode = 0
        fake_proc.stdout = json.dumps({"result": "hasil analisis", "session_id": "abc123", "total_cost_usd": 0.01})
        fake_proc.stderr = ""
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"), \
             patch("app.llm.subprocess.run", return_value=fake_proc) as mock_run:
            result = router.ask_claude_code("analisis evidence ini")
        self.assertEqual(result["mode"], "claude_code")
        self.assertEqual(result["text"], "hasil analisis")
        self.assertEqual(result["session_id"], "abc123")
        self.assertEqual(result["cost_usd"], 0.01)
        called_cmd = mock_run.call_args.args[0]
        # Safety-by-design assertions: zero tool access, subscription auth preserved.
        self.assertIn("--permission-prompts", called_cmd)
        self.assertIn("none", called_cmd)
        self.assertNotIn("--allowedTools", called_cmd)
        self.assertNotIn("--bare", called_cmd)

    def test_scratch_cwd_is_used_not_project_root(self):
        router = LLMRouter(_cfg())
        fake_proc = MagicMock()
        fake_proc.returncode = 0
        fake_proc.stdout = json.dumps({"result": "ok"})
        fake_proc.stderr = ""
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"), \
             patch("app.llm.subprocess.run", return_value=fake_proc) as mock_run:
            router.ask_claude_code("prompt")
        cwd_used = mock_run.call_args.kwargs.get("cwd")
        self.assertIsNotNone(cwd_used)
        self.assertNotEqual(str(cwd_used), str(ROOT))

    def test_timeout_raises_clear_error(self):
        router = LLMRouter(_cfg())
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"), \
             patch("app.llm.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="claude", timeout=30)):
            with self.assertRaises(RuntimeError) as ctx:
                router.ask_claude_code("prompt")
        self.assertIn("timeout", str(ctx.exception).lower())

    def test_non_json_output_raises_clear_error(self):
        router = LLMRouter(_cfg())
        fake_proc = MagicMock()
        fake_proc.returncode = 0
        fake_proc.stdout = "not json at all"
        fake_proc.stderr = ""
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"), \
             patch("app.llm.subprocess.run", return_value=fake_proc):
            with self.assertRaises(RuntimeError) as ctx:
                router.ask_claude_code("prompt")
        self.assertIn("JSON", str(ctx.exception))

    def test_empty_output_mentions_login_and_version(self):
        router = LLMRouter(_cfg())
        fake_proc = MagicMock()
        fake_proc.returncode = 1
        fake_proc.stdout = ""
        fake_proc.stderr = "error: unknown option '--permission-prompts'"
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"), \
             patch("app.llm.subprocess.run", return_value=fake_proc):
            with self.assertRaises(RuntimeError) as ctx:
                router.ask_claude_code("prompt")
        msg = str(ctx.exception)
        self.assertIn("login", msg)
        self.assertIn("v2.1.259", msg)

    def test_ask_routes_to_claude_code_when_mode_selected(self):
        router = LLMRouter(_cfg(llm_mode="claude_code"))
        with patch.object(router, "ask_claude_code", return_value={"mode": "claude_code", "text": "x"}) as mock_ask:
            result = router.ask("prompt")
        mock_ask.assert_called_once()
        self.assertEqual(result["mode"], "claude_code")

    def test_auto_mode_prefers_cloud_over_claude_code(self):
        router = LLMRouter(_cfg(llm_mode="auto", openai_api_key="sk-test"))
        self.assertEqual(router.mode(), "cloud")

    def test_auto_mode_uses_claude_code_when_enabled_and_no_cloud_key(self):
        router = LLMRouter(_cfg(llm_mode="auto", openai_api_key="", claude_code_enabled=True))
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"):
            self.assertEqual(router.mode(), "claude_code")

    def test_auto_mode_skips_claude_code_when_binary_missing(self):
        router = LLMRouter(_cfg(llm_mode="auto", openai_api_key="", claude_code_enabled=True, local_enabled=True))
        with patch("app.llm.shutil.which", return_value=None):
            self.assertEqual(router.mode(), "local")

    def test_auto_mode_skips_claude_code_when_not_enabled(self):
        router = LLMRouter(_cfg(llm_mode="auto", openai_api_key="", claude_code_enabled=False, local_enabled=True))
        with patch("app.llm.shutil.which", return_value="/usr/local/bin/claude"):
            self.assertEqual(router.mode(), "local")


class ReasonWithSkillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_extra = {"root": self.tmp.name, "data_root": self.tmp.name}
        init_db(self.cfg_extra)
        seed_builtin_skills(self.cfg_extra)

    def tearDown(self):
        self.tmp.cleanup()

    def test_auto_selects_skill_and_routes_through_ask(self):
        router = LLMRouter(_cfg(llm_mode="cloud", **self.cfg_extra))
        with patch.object(router, "ask", return_value={"mode": "cloud", "text": "analysis"}) as mock_ask:
            result = router.reason_with_skill("apache 2.4.49 metasploit module check")
        mock_ask.assert_called_once()
        prompt_used = mock_ask.call_args.args[0]
        self.assertIn("ASEP CORE AUTHORITY", prompt_used)
        self.assertIn("metasploit_intelligence", result["skill_ids"])
        self.assertEqual(result["text"], "analysis")

    def test_explicit_skill_ids_override_auto_selection(self):
        router = LLMRouter(_cfg(llm_mode="cloud", **self.cfg_extra))
        with patch.object(router, "ask", return_value={"mode": "cloud", "text": "x"}) as mock_ask:
            result = router.reason_with_skill("irrelevant text", skill_ids=["wireless_intelligence"])
        self.assertEqual(result["skill_ids"], ["wireless_intelligence"])
        prompt_used = mock_ask.call_args.args[0]
        self.assertIn("Wireless Intelligence", prompt_used)

    def test_reason_with_skill_falls_through_to_none_mode_gracefully(self):
        router = LLMRouter(_cfg(llm_mode="auto", openai_api_key="", claude_code_enabled=False, local_enabled=False, **self.cfg_extra))
        result = router.reason_with_skill("some evidence")
        self.assertEqual(result["mode"], "none")
        self.assertIn("skill_ids", result)

    def test_all_75_skills_are_eligible_for_selection(self):
        # Confirms reason_with_skill draws from the full registry, not a
        # leftover static 18-skill subset.
        router = LLMRouter(_cfg(llm_mode="cloud", **self.cfg_extra))
        with patch.object(router, "ask", return_value={"mode": "cloud", "text": "x"}):
            result = router.reason_with_skill(
                "meterpreter session established, check persistence assessment and privilege context"
            )
        self.assertTrue(any(sid in result["skill_ids"] for sid in
                             ["persistence_assessment_intelligence", "privilege_context_intelligence", "session_intelligence"]))


class IntelligenceStatusRouteTest(unittest.TestCase):
    """Regression test for the /api/intelligence/status fix: the route must
    report llm.mode() (the same resolution LLMRouter.ask() actually uses at
    call time) instead of a separately hand-rolled local/cloud-only guess
    that had no notion of the claude_code backend at all.
    """

    def test_intelligence_status_uses_llm_mode_not_hardcoded_heuristic(self):
        source = (ROOT / "app" / "routes.py").read_text(encoding="utf-8")
        start = source.index('@app.get("/api/intelligence/status")')
        end = source.index("@app.get", start + 1)
        block = source[start:end]
        self.assertIn("llm.mode()", block)
        self.assertIn("claude_code", block)
        # The old heuristic string must not still be driving this endpoint.
        self.assertNotIn('"hybrid" if local["enabled"] and cloud["configured"]', block)

    def test_settings_ui_surfaces_claude_code_status(self):
        js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("loadSettings", js)
        start = js.index("async function loadSettings")
        end = js.index("\n", js.index("}catch(e){toast(e.message)}}", start))
        block = js[start:end]
        self.assertIn("claude_code", block)
        self.assertIn("Claude Code", block)


if __name__ == "__main__":
    unittest.main()
