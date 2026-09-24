import unittest
from pathlib import Path
import ast

class UXContractTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.html = (self.root / "templates" / "index.html").read_text(encoding="utf-8")
        self.js = (self.root / "static" / "app.js").read_text(encoding="utf-8")
        self.css = (self.root / "static" / "app.css").read_text(encoding="utf-8")

    def test_ux_files_exist(self):
        for rel in ["app/ux.py", "ASEP_UX_V2.9.md", "VERSION", "templates/index.html", "static/app.js", "static/app.css"]:
            self.assertTrue((self.root / rel).exists(), rel)

    def test_required_ux_api_contracts_are_declared(self):
        text = (self.root / "app" / "routes.py").read_text(encoding="utf-8")
        for route in [
            "/api/v2/dashboard", "/api/v2/targets", "/api/v2/evidence", "/api/v2/findings",
            "/api/v2/attack-paths", "/api/v2/recommendations", "/api/v2/sessions",
            "/api/v2/activity", "/api/v2/capabilities", "/api/v2/environment", "/api/v2/discovery-history", "/api/v2/intelligence/summary"
        ]:
            self.assertIn(route, text)

    def test_ux_principles_are_present(self):
        for token in ["UNDERSTAND", "DISCOVER", "ANALYZE", "VALIDATE", "EXPLOIT", "POST-EXPLOIT", "ACHIEVE"]:
            self.assertIn(token, self.html + self.js)
        for token in ["Next Best Action", "Attack Graph", "Evidence", "Findings", "Sessions", "Scope", "Active Hosts", "Environment Awareness", "Host discovery only"]:
            self.assertIn(token, self.html + self.js)

    def test_version_is_current_release(self):
        self.assertEqual((self.root / "VERSION").read_text(encoding="utf-8").strip(), "2.9.34")
        self.assertIn("2.9.34", (self.root / "release.json").read_text(encoding="utf-8"))
    def test_automatic_network_awareness_contract(self):
        js = (self.root / "static" / "app.js").read_text(encoding="utf-8")
        html = (self.root / "templates" / "index.html").read_text(encoding="utf-8")
        self.assertIn("30000", js)
        self.assertIn("10000", js)
        self.assertIn("dashboardEnvironment", html)
        self.assertIn("awarenessStatus", html)


if __name__ == "__main__":
    unittest.main()
