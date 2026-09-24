import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.config import load_config


class ConfigSecurityTests(unittest.TestCase):
    def test_root_approval_required_is_configurable_and_defaults_true(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ASEP_ROOT_APPROVAL_REQUIRED", None)
            cfg = load_config()
            self.assertTrue(cfg["root_approval_required"])
        with patch.dict(os.environ, {"ASEP_ROOT_APPROVAL_REQUIRED": "false"}, clear=False):
            cfg = load_config()
            self.assertFalse(cfg["root_approval_required"])

    def test_remote_auth_configuration_is_loaded(self):
        with patch.dict(os.environ, {"ASEP_HOST": "0.0.0.0", "ASEP_AUTH_USER": "lab", "ASEP_AUTH_PASSWORD": "secret"}, clear=False):
            cfg = load_config()
            self.assertEqual(cfg["auth_user"], "lab")
            self.assertEqual(cfg["auth_password"], "secret")


if __name__ == "__main__":
    unittest.main()
