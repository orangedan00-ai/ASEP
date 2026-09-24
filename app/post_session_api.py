
from .post_session_intelligence import SessionContext, summarize_session

def build_post_session_advice(payload):
    payload = payload or {}
    session = SessionContext(
        session_id=str(payload.get("session_id", "")),
        target=str(payload.get("target", "")),
        platform=str(payload.get("platform", "unknown")),
        session_type=str(payload.get("session_type", "unknown")),
        user=str(payload.get("user", "unknown")),
        privilege=str(payload.get("privilege", "unknown")),
        domain=str(payload.get("domain", "")),
        interfaces=list(payload.get("interfaces", []) or []),
        evidence=list(payload.get("evidence", []) or []),
        objective=str(payload.get("objective", "")),
    )
    return summarize_session(session)
