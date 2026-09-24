
"""Versioned ASEP capability library metadata."""
SKILLS = {
    "adaptive_reasoning": {"version": "2.0", "category": "reasoning", "status": "active", "validation": "unit-tested"},
    "universal_metasploit": {"version": "1.0", "category": "exploitation", "status": "active", "validation": "unit-tested"},
    "post_session_intelligence": {"version": "2.0", "category": "post-session", "status": "active", "validation": "unit-tested"},
    "target_path_passive_deep_dive": {"version": "2.0", "category": "attack-path", "status": "active", "validation": "unit-tested"},
    "capability_router": {"version": "2.0", "category": "orchestration", "status": "active", "validation": "unit-tested"},
    "autonomous_replanning": {"version": "1.0", "category": "reasoning", "status": "active", "validation": "unit-tested"},
    "self_healing": {"version": "3.0", "category": "reliability", "status": "active", "validation": "unit-tested"},
    "self_modifying": {"version": "1.0", "category": "self-improvement", "status": "active", "validation": "unit-tested"},
    "evidence_correlation": {"version": "2.0", "category": "evidence", "status": "active", "validation": "unit-tested"},
    "deception_detection": {"version": "1.0", "category": "deception-awareness", "status": "active", "validation": "unit-tested"},
}
def inventory():
    return SKILLS
