import unittest
from unittest.mock import patch

from app.llm import LLMRouter


class OptionalOpenAITest(unittest.TestCase):
    def test_none_mode_does_not_require_openai_sdk(self):
        cfg = {
            "llm_mode": "auto",
            "openai_api_key": "",
            "local_enabled": False,
        }
        router = LLMRouter(cfg)
        result = router.ask("test")
        self.assertEqual(result["mode"], "none")

    def test_cloud_mode_has_clear_error_when_openai_missing(self):
        cfg = {
            "llm_mode": "cloud",
            "openai_api_key": "dummy",
            "local_enabled": False,
            "cloud_model": "gpt-5.6-luna",
        }
        router = LLMRouter(cfg)
        with patch.dict("sys.modules", {"openai": None}):
            with self.assertRaisesRegex(RuntimeError, "package 'openai' belum terpasang"):
                router.ask_cloud("test")


if __name__ == "__main__":
    unittest.main()
