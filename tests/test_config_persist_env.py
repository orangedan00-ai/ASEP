import tempfile
import unittest
from pathlib import Path

from app.config import persist_env_var


class PersistEnvVarTest(unittest.TestCase):
    def test_replaces_existing_key_preserving_other_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text(
                "# comment line\nOPENAI_API_KEY=sk-secret\nASEP_LLM_MODE=auto\nASEP_LOCAL_ENABLED=true\n",
                encoding="utf-8",
            )
            persist_env_var(root, "ASEP_LLM_MODE", "claude_code")
            content = (root / ".env").read_text(encoding="utf-8")
        self.assertIn("ASEP_LLM_MODE=claude_code", content)
        self.assertIn("OPENAI_API_KEY=sk-secret", content)  # untouched
        self.assertIn("# comment line", content)  # untouched
        self.assertIn("ASEP_LOCAL_ENABLED=true", content)  # untouched
        self.assertNotIn("ASEP_LLM_MODE=auto", content)

    def test_appends_key_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("OPENAI_API_KEY=sk-secret\n", encoding="utf-8")
            persist_env_var(root, "ASEP_LLM_MODE", "local")
            content = (root / ".env").read_text(encoding="utf-8")
        self.assertIn("ASEP_LLM_MODE=local", content)
        self.assertIn("OPENAI_API_KEY=sk-secret", content)

    def test_creates_env_file_when_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            persist_env_var(root, "ASEP_LLM_MODE", "cloud")
            content = (root / ".env").read_text(encoding="utf-8")
        self.assertEqual(content.strip(), "ASEP_LLM_MODE=cloud")

    def test_does_not_match_similarly_prefixed_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".env").write_text("ASEP_LLM_MODE_OLD=weird\nASEP_LLM_MODE=auto\n", encoding="utf-8")
            persist_env_var(root, "ASEP_LLM_MODE", "local")
            content = (root / ".env").read_text(encoding="utf-8")
        self.assertIn("ASEP_LLM_MODE_OLD=weird", content)
        self.assertIn("ASEP_LLM_MODE=local", content)
        self.assertNotIn("ASEP_LLM_MODE=auto", content)


if __name__ == "__main__":
    unittest.main()
