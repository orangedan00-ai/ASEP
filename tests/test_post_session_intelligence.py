
from app.post_session_intelligence import SessionContext, recommend_next_actions, summarize_session

def test_standard_user_gets_context_recommendation():
    s = SessionContext(
        session_id="3",
        target="10.0.0.10",
        platform="Windows",
        session_type="meterpreter",
        user="CORP\\user",
        privilege="standard",
        domain="CORP",
        interfaces=[{"name":"eth0"}, {"name":"eth1"}],
        objective="authorized assessment",
    )
    ids = [x.action_id for x in recommend_next_actions(s)]
    assert "PROFILE_HOST" in ids
    assert "ANALYZE_NETWORK_PATH" in ids
    assert "ANALYZE_DOMAIN_RELATIONSHIPS" in ids
    assert "UPDATE_ATTACK_GRAPH" in ids
    assert "PRESERVE_EVIDENCE" in ids

def test_advice_does_not_auto_execute():
    s = SessionContext(session_id="1", target="host")
    advice = summarize_session(s)
    assert advice["session_id"] == "1"
    assert all("requires_approval" in r for r in advice["recommendations"])

def test_evidence_preservation_is_available():
    s = SessionContext(session_id="7", target="host", privilege="administrator")
    ids = [x.action_id for x in recommend_next_actions(s)]
    assert "PRESERVE_EVIDENCE" in ids
