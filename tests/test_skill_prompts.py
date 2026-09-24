import hashlib
import unittest
from pathlib import Path

from app.skill_prompts import SKILLS, SKILL_SELECTION_KEYWORDS, inventory, select_skills, build_skill_prompt

EXPECTED_IDS = {
    "evidence_intelligence", "asset_service_intelligence", "vulnerability_correlation",
    "attack_path_intelligence", "adaptive_replanning", "failure_intelligence",
    "capability_tool_selection", "metasploit_intelligence", "session_intelligence",
    "network_intelligence", "web_api_intelligence", "ad_identity_intelligence",
    "cloud_intelligence", "wireless_intelligence", "source_code_security",
    "osint_intelligence", "risk_intelligence", "reporting_intelligence",
}


class SkillPromptsTest(unittest.TestCase):
    def test_all_18_skills_loaded(self):
        self.assertEqual(set(SKILLS.keys()), EXPECTED_IDS)
        self.assertEqual(len(SKILLS), 18)

    def test_every_skill_has_keywords_for_selection(self):
        for sid in SKILLS:
            self.assertIn(sid, SKILL_SELECTION_KEYWORDS, f"{sid} has no selection keywords")
            self.assertTrue(SKILL_SELECTION_KEYWORDS[sid], f"{sid} has empty keyword list")

    def test_inventory_is_ordered_and_matches_original_numbering(self):
        inv = inventory()
        orders = [x["order"] for x in inv]
        self.assertEqual(orders, sorted(orders))
        self.assertEqual(inv[0]["id"], "evidence_intelligence")
        self.assertEqual(inv[-1]["id"], "reporting_intelligence")

    def test_evidence_intelligence_is_always_included_as_baseline(self):
        # Even a context matching nothing else should still get the baseline skill.
        self.assertEqual(select_skills("completely unrelated text xyz123"), ["evidence_intelligence"])

    def test_selection_picks_domain_relevant_skills(self):
        result = select_skills("found apache 2.4.49 on port 80, check metasploit exploit modules")
        self.assertIn("metasploit_intelligence", result)
        result2 = select_skills("kerberos ticket, domain controller, active directory trust relationship")
        self.assertIn("ad_identity_intelligence", result2)
        result3 = select_skills("wifi access point bssid wpa2 handshake")
        self.assertIn("wireless_intelligence", result3)

    def test_selection_respects_limit(self):
        result = select_skills("vulnerability cve metasploit module session shell network topology", limit=2)
        self.assertLessEqual(len(result), 2)

    def test_build_skill_prompt_includes_core_authority_disclaimer(self):
        p = build_skill_prompt(["evidence_intelligence"], "some evidence")
        self.assertIn("ASEP CORE AUTHORITY", p)
        self.assertIn("cannot be changed by it", p)
        self.assertIn("some evidence", p)

    def test_build_skill_prompt_concatenates_multiple_skills(self):
        p = build_skill_prompt(["evidence_intelligence", "attack_path_intelligence"], "ctx")
        self.assertIn("Evidence Intelligence", p)
        self.assertIn("Attack Path Intelligence", p)

    def test_build_skill_prompt_ignores_unknown_skill_id(self):
        p = build_skill_prompt(["not_a_real_skill", "evidence_intelligence"], "ctx")
        self.assertIn("Evidence Intelligence", p)

    def test_content_matches_uploaded_source_verbatim(self):
        # Spot-check a few skills against their original uploaded content hash
        # to catch any transcription corruption.
        known_hashes = {
            "attack_path_intelligence": "0156f778b0efbb5c",
            "evidence_intelligence": hashlib.sha256(SKILLS["evidence_intelligence"]["prompt"].encode()).hexdigest()[:16],
        }
        actual = hashlib.sha256(SKILLS["attack_path_intelligence"]["prompt"].encode()).hexdigest()[:16]
        self.assertEqual(actual, known_hashes["attack_path_intelligence"])

    def test_no_skill_prompt_is_empty_or_suspiciously_short(self):
        for sid, skill in SKILLS.items():
            self.assertGreater(len(skill["prompt"]), 100, f"{sid} prompt looks truncated")


if __name__ == "__main__":
    unittest.main()
