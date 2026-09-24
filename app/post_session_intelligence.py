
"""Evidence-driven post-session advisor for ASEP."""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SessionContext:
    session_id: str
    target: str
    platform: str = "unknown"
    session_type: str = "unknown"
    user: str = "unknown"
    privilege: str = "unknown"
    domain: str = ""
    interfaces: List[Dict] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    objective: str = ""


@dataclass
class Recommendation:
    action_id: str
    title: str
    reason: str
    evidence: List[str]
    confidence: str
    risk: str
    priority: int
    requires_approval: bool = True


def recommend_next_actions(session: SessionContext) -> List[Recommendation]:
    recs = []

    if session.privilege.lower() in {"unknown", "standard", "user", "low"}:
        recs.append(Recommendation(
            "PROFILE_HOST",
            "Profile current security context",
            "Current privilege is not established at an elevated level; understand identity and security context first.",
            ["session privilege state"],
            "HIGH", "LOW", 1, True,
        ))

    if len(session.interfaces) > 1:
        recs.append(Recommendation(
            "ANALYZE_NETWORK_PATH",
            "Analyze network path",
            "Multiple interfaces were observed; correlate them with already-known assets and authorized scope.",
            ["multiple network interfaces observed"],
            "MEDIUM", "LOW", 2, True,
        ))

    if session.domain:
        recs.append(Recommendation(
            "ANALYZE_DOMAIN_RELATIONSHIPS",
            "Analyze identity/domain relationships",
            "Domain context exists; correlate identity, group, trust and asset evidence already collected.",
            [f"domain context: {session.domain}"],
            "MEDIUM", "LOW", 2, True,
        ))

    recs.append(Recommendation(
        "UPDATE_ATTACK_GRAPH",
        "Update attack graph",
        "A live session is new evidence and may change paths and assumptions.",
        ["established session"],
        "HIGH", "LOW", 1, False,
    ))

    recs.append(Recommendation(
        "PRESERVE_EVIDENCE",
        "Preserve session evidence",
        "Capture current session context before consequential actions.",
        ["established session"],
        "HIGH", "LOW", 1, False,
    ))

    return sorted(recs, key=lambda x: (x.priority, x.action_id))


def summarize_session(session: SessionContext) -> Dict:
    return {
        "session_id": session.session_id,
        "target": session.target,
        "platform": session.platform,
        "session_type": session.session_type,
        "user": session.user,
        "privilege": session.privilege,
        "domain": session.domain,
        "interfaces": len(session.interfaces),
        "objective": session.objective,
        "recommendations": [r.__dict__ for r in recommend_next_actions(session)],
    }
