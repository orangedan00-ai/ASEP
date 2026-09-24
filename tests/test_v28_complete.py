
import os
import tempfile
import unittest
from pathlib import Path

from app.metasploit_universal import (
    MetasploitModule, TargetFingerprint, match_modules, build_validation_plan
)
from app.post_session_intelligence import SessionContext, recommend_next_actions
from app.target_path import CandidateAsset, passive_deep_dive
from app.capability_router import SecurityObjective, recommend_capabilities
from app.replanner import PlanState, Replanner
from app.self_modifying import SelfModifier


class V28CompleteTests(unittest.TestCase):
    def test_universal_metasploit_non_windows_session_candidate(self):
        fp = TargetFingerprint(
            target="10.10.10.20",
            platform="linux",
            architecture="x64",
            services=["http"],
            versions={"http": "example"},
            evidence=[{"type": "service_fingerprint"}],
        )
        module = MetasploitModule(
            name="exploit/example/linux_http",
            platforms=["linux"],
            services=["http"],
            architectures=["x64"],
            expected_outcomes=["session"],
            session_types=["meterpreter"],
        )
        matches = match_modules(fp, [module])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["expected_outcomes"], ["session"])
        self.assertEqual(build_validation_plan(fp, matches[0])["phase"], "CHECK")

    def test_post_session_advice(self):
        s = SessionContext(
            session_id="3", target="host", platform="Linux",
            session_type="meterpreter", user="user", privilege="standard",
            domain="LAB", interfaces=[{"name": "eth0"}, {"name": "eth1"}],
        )
        ids = {x.action_id for x in recommend_next_actions(s)}
        self.assertIn("PROFILE_HOST", ids)
        self.assertIn("ANALYZE_NETWORK_PATH", ids)
        self.assertIn("ANALYZE_DOMAIN_RELATIONSHIPS", ids)
        self.assertIn("UPDATE_ATTACK_GRAPH", ids)

    def test_passive_deep_dive_blocks_active_out_of_scope(self):
        c = CandidateAsset(
            "10.20.30.40", "OUT_OF_SCOPE",
            evidence=[{"type": "certificate"}],
            relationships=[{"weight": 0.2, "reason": "shared certificate"}],
        )
        result = passive_deep_dive(c)
        self.assertTrue(result["passive_only"])
        self.assertTrue(result["requires_confirmation"])
        self.assertFalse(result["active_testing_allowed"])

    def test_capability_router_is_objective_driven(self):
        result = recommend_capabilities(SecurityObjective(
            "Assess web API authorization and domain identity relationships",
            evidence=[{"service": "HTTP API"}, {"context": "domain"}],
        ))
        names = {x["name"] for x in result}
        self.assertIn("Web & API Security", names)
        self.assertIn("Identity & Directory", names)
        self.assertIn("Attack Path & Graph", names)

    def test_replanner_adapts_after_failure(self):
        result = Replanner().replan(PlanState(
            objective="validate security boundary",
            failed_actions=[{"action_id": "TRY_ALTERNATIVE_CAPABILITY"}],
            blocked_paths=[{"path": ["A", "B"]}],
        ))
        self.assertTrue(result["adapted"])
        self.assertNotIn(
            "TRY_ALTERNATIVE_CAPABILITY",
            [x["action_id"] for x in result["candidate_actions"]
             if x["action_id"] in {"TRY_ALTERNATIVE_CAPABILITY"}]
        )

    def test_self_modifying_checkpoint_and_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "data").mkdir()
            (root / "app").mkdir()
            (root / "tests").mkdir()
            (root / "app" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests" / "test_sample.py").write_text(
                "import unittest\n"
                "from app.sample import VALUE\n"
                "class T(unittest.TestCase):\n"
                "  def test_value(self): self.assertEqual(VALUE, 2)\n",
                encoding="utf-8"
            )
            modifier = SelfModifier(root)
            # Expected failure must rollback the patch.
            result = modifier.apply_and_validate({"app/sample.py": "VALUE = 3\n"}, run_tests=True)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "ROLLED_BACK")
            self.assertEqual((root / "app" / "sample.py").read_text(), "VALUE = 1\n")


if __name__ == "__main__":
    unittest.main()
