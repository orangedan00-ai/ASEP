import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DashboardResourceUXTests(unittest.TestCase):
    def test_resource_health_thresholds_and_labels(self):
        js = (ROOT / "static" / "app.js").read_text()
        self.assertIn("if(v>=95)return {key:'critical',label:'CRITICAL'}", js)
        self.assertIn("if(v>=80)return {key:'high',label:'HIGH'}", js)
        self.assertIn("if(v>=60)return {key:'moderate',label:'MODERATE'}", js)
        self.assertIn("return {key:'low',label:'LOW'}", js)

    def test_resource_cards_have_non_color_status(self):
        html = (ROOT / "templates" / "index.html").read_text()
        for item in ("resourceCpuStatus", "resourceMemStatus", "resourceDiskStatus"):
            self.assertIn(item, html)

    def test_resource_css_states(self):
        css = (ROOT / "static" / "app.css").read_text()
        for state in ("resource-low", "resource-moderate", "resource-high", "resource-critical"):
            self.assertIn(state, css)

if __name__ == "__main__":
    unittest.main()
