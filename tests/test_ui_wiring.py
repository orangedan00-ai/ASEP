from pathlib import Path
import unittest


class UIWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.js = (root / "static" / "app.js").read_text(encoding="utf-8")
        cls.html = (root / "templates" / "index.html").read_text(encoding="utf-8")

    def test_load_capabilities_is_defined_once(self):
        self.assertEqual(self.js.count("async function loadCapabilities()"), 1)

    def test_required_engine_endpoints_are_wired(self):
        endpoints = [
            "/api/tools", "/api/tools/plan", "/api/tools/run", "/api/tools/execute-chain",
            "/api/target-path/passive-deep-dive", "/api/adaptive/analyze", "/api/replan",
            "/api/windows/fingerprint", "/api/wireless/chain", "/api/self-modifying/apply",
            "/api/shell", "/api/sudo",
        ]
        # UI functions must contain the route strings so the controls cannot silently become dead buttons.
        for endpoint in endpoints:
            self.assertIn(endpoint, self.js, endpoint)

    def test_control_surface_elements_exist(self):
        for element_id in [
            "toolInventoryBtn", "toolPlanBtn", "toolRunBtn", "chainRunBtn",
            "passiveDeepDiveBtn", "adaptiveAnalyzeBtn", "replanBtn",
            "windowsFingerprintBtn", "wirelessChainBtn", "shellRunBtn",
            "sudoRunBtn", "selfModifyApplyBtn",
        ]:
            self.assertIn(f'id="{element_id}"', self.html)


if __name__ == "__main__":
    unittest.main()


class TargetInventoryServiceUIWiringTests(unittest.TestCase):
    def test_dashboard_is_ports_only_and_target_inventory_has_metasploit_action(self):
        text=Path("static/app.js").read_text()
        self.assertIn("IDENTIFIED PORTS", text)
        self.assertIn("openMetasploitForTarget", text)
        self.assertIn("METASPLOIT", text)



def test_exploitation_uses_remote_checkable_os_filtered_ui():
    html=(ROOT/'templates'/'index.html').read_text()
    js=(ROOT/'static'/'app.js').read_text()
    assert 'Advanced manual module search' not in html
    assert 'msfCheckPanel' in html
    assert 'RUN — LOCKED: CHECK REQUIRED' in html
    assert 'Filtering remote CHECK-capable modules from Nmap OS/service evidence' in js

def test_dashboard_deep_scan_dot_and_resource_chart_colors():
    js=(ROOT/'static'/'app.js').read_text()
    css=(ROOT/'static'/'app.css').read_text()
    assert 'deep-scan-dot' in js
    assert 'healthColor' in js
    assert '#42d392' in css

def test_skill_reasoning_panel_and_cross_page_entry_points_are_wired():
    html=(ROOT/'templates'/'index.html').read_text()
    js=(ROOT/'static'/'app.js').read_text()
    # The panel itself
    assert 'skillReasonSelect' in html
    assert 'skillReasonContext' in html
    assert 'skillReasonResult' in html
    # The global connector function, defined exactly once
    assert js.count('async function runSkillReasoning(') == 1
    assert js.count('async function loadSkillOptions(') == 1
    # Cross-page entry points actually call the connector
    assert 'runSkillReasoning(' in js  # called from loadExploitCandidates
    assert 'analyzePathsWithSkill()' in html  # Attack Paths page button
    assert js.count('function analyzePathsWithSkill(') == 1
