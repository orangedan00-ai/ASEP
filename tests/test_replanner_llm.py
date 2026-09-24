import unittest
from unittest.mock import MagicMock

from app.replanner import PlanState, Replanner


class ReplannerLlmEnrichmentTest(unittest.TestCase):
    def test_no_llm_produces_identical_result_to_before(self):
        # Backward-compat: Replanner() with zero args must behave exactly as
        # it did before this feature existed.
        result = Replanner().replan(PlanState(objective="test"))
        self.assertNotIn("llm_reasoning", result)
        self.assertIn("candidate_actions", result)

    def test_llm_reasoning_added_when_llm_available(self):
        fake_llm = MagicMock()
        fake_llm.mode.return_value = "cloud"
        fake_llm.reason_with_skill.return_value = {
            "mode": "cloud", "text": "Recommend validating assumption X first.",
            "skill_ids": ["adaptive_replanning", "failure_intelligence"],
        }
        result = Replanner(llm=fake_llm).replan(PlanState(objective="test", failed_actions=[{"action_id": "X"}]))
        self.assertIn("llm_reasoning", result)
        self.assertEqual(result["llm_reasoning"]["mode"], "cloud")
        self.assertIn("candidate_actions", result)  # deterministic list still present, unchanged shape
        fake_llm.reason_with_skill.assert_called_once()
        used_skills = fake_llm.reason_with_skill.call_args.kwargs.get("skill_ids")
        self.assertEqual(used_skills, ["adaptive_replanning", "failure_intelligence"])

    def test_llm_reasoning_skipped_when_llm_mode_is_none(self):
        fake_llm = MagicMock()
        fake_llm.mode.return_value = "none"
        result = Replanner(llm=fake_llm).replan(PlanState(objective="test"))
        self.assertNotIn("llm_reasoning", result)
        fake_llm.reason_with_skill.assert_not_called()

    def test_llm_failure_does_not_break_replanning(self):
        fake_llm = MagicMock()
        fake_llm.mode.return_value = "cloud"
        fake_llm.reason_with_skill.side_effect = RuntimeError("backend timeout")
        result = Replanner(llm=fake_llm).replan(PlanState(objective="test"))
        # Deterministic candidates must still be present and correct...
        self.assertTrue(result["candidate_actions"])
        # ...and the failure is surfaced, not swallowed silently or raised.
        self.assertEqual(result["llm_reasoning"]["mode"], "error")
        self.assertIn("backend timeout", result["llm_reasoning"]["text"])

    def test_deterministic_candidates_unchanged_by_llm_presence(self):
        # The exact same objective/state must produce the exact same
        # deterministic candidate_actions whether or not an LLM is attached --
        # the LLM only adds a field, never reorders or filters the baseline.
        state = PlanState(objective="test", failed_actions=[{"action_id": "TRY_ALTERNATIVE_CAPABILITY"}])
        without_llm = Replanner().replan(state)
        fake_llm = MagicMock()
        fake_llm.mode.return_value = "cloud"
        fake_llm.reason_with_skill.return_value = {"mode": "cloud", "text": "x", "skill_ids": []}
        with_llm = Replanner(llm=fake_llm).replan(state)
        self.assertEqual(without_llm["candidate_actions"], with_llm["candidate_actions"])


if __name__ == "__main__":
    unittest.main()
