
import ast
from pathlib import Path
import unittest

ROUTES = {
    "/api/metasploit/universal/match",
    "/api/post-session/advice",
    "/api/target-path/passive-deep-dive",
    "/api/capabilities/recommend",
    "/api/replan",
    "/api/self-modifying/preview",
    "/api/self-modifying/apply",
    "/api/self-heal/health",
    "/api/tools",
    "/api/tools/plan",
    "/api/tools/run",
    "/api/tools/execute-chain",
    "/api/windows/fingerprint",
    "/api/wireless/chain",
    "/api/self-modifying/apply",
    "/api/shell",
    "/api/sudo",
    "/api/adaptive/analyze",
    "/api/evidence",
    "/api/environment",
    "/api/network-discovery/start",
    "/api/network-discovery/status",
    "/api/network-discovery/history",
    "/api/v2/environment",
    "/api/v2/discovery-history",
}

class RouteContractTest(unittest.TestCase):
    def test_required_routes_exist(self):
        p = Path(__file__).resolve().parents[1] / "app" / "routes.py"
        tree = ast.parse(p.read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for d in node.decorator_list:
                    if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute):
                        if isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                            found.add(d.args[0].value)
        missing = ROUTES - found
        self.assertFalse(missing, f"Missing routes: {sorted(missing)}")
