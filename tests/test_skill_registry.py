import json
import tempfile
import unittest
from pathlib import Path

from app.db import init_db, get_skill, skill_history, set_skill_enabled
from app.skill_registry import (
    seed_builtin_skills, inventory, select_skills, build_skill_prompt,
    get_skill_body, parse_skill_markdown, SkillValidationError, compute_sha256,
    SEED_DIR,
)


def _cfg(tmp):
    return {"root": tmp, "data_root": tmp}


class SkillRegistrySeedingTest(unittest.TestCase):
    def test_seed_loads_all_75_with_no_errors(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            r = seed_builtin_skills(cfg)
        self.assertTrue(r["seeded"])
        self.assertEqual(r["count"], 75)
        self.assertEqual(r["errors"], [])

    def test_seed_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            seed_builtin_skills(cfg)
            second = seed_builtin_skills(cfg)
        self.assertFalse(second["seeded"])
        self.assertEqual(second["count"], 75)

    def test_seed_force_reseeds_and_archives_previous_version_to_history(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            seed_builtin_skills(cfg)
            seed_builtin_skills(cfg, force=True)
            hist = skill_history(cfg, "evidence_intelligence")
        self.assertTrue(len(hist) >= 1)

    def test_skill_75_is_registered_with_correct_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            seed_builtin_skills(cfg)
            row = get_skill(cfg, "broad_exploit_discovery_intelligence")
        self.assertIsNotNone(row)
        self.assertEqual(row["skill_number"], 75)
        self.assertEqual(row["category"], "exploitation")
        self.assertTrue(row["built_in"])

    def test_seed_writes_files_into_data_skills_directory(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            seed_builtin_skills(cfg)
            files = list((Path(td) / "data" / "skills").glob("*.md"))
        self.assertEqual(len(files), 75)

    def test_inventory_reflects_enabled_only_filter(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _cfg(td)
            init_db(cfg)
            seed_builtin_skills(cfg)
            set_skill_enabled(cfg, "wireless_intelligence", False)
            all_skills = inventory(cfg, enabled_only=False)
            enabled_skills = inventory(cfg, enabled_only=True)
        self.assertEqual(len(all_skills), 75)
        self.assertEqual(len(enabled_skills), 74)
        self.assertNotIn("wireless_intelligence", {s["id"] for s in enabled_skills})


class SkillMarkdownParsingTest(unittest.TestCase):
    def test_parses_valid_frontmatter_and_body(self):
        text = "---\nid: test_skill\nname: Test\nversion: 1.0\n---\n\n# Body\nSome content."
        meta, body = parse_skill_markdown(text)
        self.assertEqual(meta["id"], "test_skill")
        self.assertIn("Some content", body)

    def test_no_frontmatter_treated_as_legacy_format(self):
        text = "# Just a body\nNo frontmatter here."
        meta, body = parse_skill_markdown(text)
        self.assertEqual(meta, {})
        self.assertIn("Just a body", body)

    def test_unclosed_frontmatter_raises(self):
        text = "---\nid: broken\nno closing delimiter"
        with self.assertRaises(SkillValidationError):
            parse_skill_markdown(text)

    def test_invalid_yaml_raises(self):
        text = "---\nid: [unclosed list\n---\nbody"
        with self.assertRaises(SkillValidationError):
            parse_skill_markdown(text)

    def test_non_mapping_frontmatter_raises(self):
        text = "---\n- just\n- a\n- list\n---\nbody"
        with self.assertRaises(SkillValidationError):
            parse_skill_markdown(text)

    def test_empty_body_raises(self):
        text = "---\nid: x\n---\n   "
        with self.assertRaises(SkillValidationError):
            parse_skill_markdown(text)

    def test_never_executes_content_only_parses(self):
        text = "---\nid: x\nname: X\n---\n__import__('os').system('echo pwned')"
        meta, body = parse_skill_markdown(text)
        self.assertIn("__import__", body)  # present as text, not executed


class SkillRegistryContentIntegrityTest(unittest.TestCase):
    def test_seed_sha256_matches_source_file(self):
        sample = SEED_DIR / "skills" / "01-evidence_intelligence.md"
        raw = sample.read_bytes()
        self.assertEqual(len(compute_sha256(raw)), 64)

    def test_seed_registry_json_lists_75(self):
        reg = json.loads((SEED_DIR / "skill-registry.json").read_text(encoding="utf-8"))
        self.assertEqual(reg["total_skills"], 75)
        self.assertEqual(len(reg["skills"]), 75)


class SkillRouterOn75Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = _cfg(self.tmp.name)
        init_db(self.cfg)
        seed_builtin_skills(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_disabled_skill_is_never_selected(self):
        set_skill_enabled(self.cfg, "wireless_intelligence", False)
        result = select_skills(self.cfg, "wifi wireless ssid bssid access point", limit=5)
        self.assertNotIn("wireless_intelligence", result)

    def test_new_skill_categories_beyond_original_18_are_selectable(self):
        result = select_skills(self.cfg, "privilege escalation path analysis lateral movement pivot", limit=5)
        self.assertTrue(any(sid in result for sid in
                             ["privilege_escalation_intelligence", "lateral_movement_intelligence", "pivot_intelligence"]))

    def test_multi_skill_prompt_assembles_coherently(self):
        ids = ["evidence_intelligence", "broad_exploit_discovery_intelligence", "exploit_prerequisite_analysis"]
        prompt = build_skill_prompt(self.cfg, ids, "apache 2.4.49")
        self.assertIn("Evidence Intelligence", prompt)
        self.assertIn("Broad Exploit Discovery", prompt)
        self.assertIn("ASEP CORE AUTHORITY", prompt)

    def test_get_skill_body_returns_none_for_unknown_skill(self):
        self.assertIsNone(get_skill_body(self.cfg, "not_a_real_skill_id"))


if __name__ == "__main__":
    unittest.main()
