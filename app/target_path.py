
"""Evidence-backed target path discovery and passive deep-dive policy."""
from dataclasses import dataclass, field
from typing import Dict, List


PASSIVE_TYPES = {
    "dns", "certificate", "hostname", "domain", "asn", "whois",
    "existing_service_reference", "existing_architecture_reference",
    "observed_relationship",
}


@dataclass
class CandidateAsset:
    target: str
    scope_status: str = "UNKNOWN"
    evidence: List[Dict] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)
    confidence: float = 0.0
    passive_only: bool = True


def passive_deep_dive(candidate: CandidateAsset) -> Dict:
    score = 0.0
    reasons = []

    for ev in candidate.evidence:
        kind = str(ev.get("type", "")).lower()
        if kind in PASSIVE_TYPES:
            score += 0.15
            reasons.append(f"correlated:{kind}")

    for rel in candidate.relationships:
        try:
            score += float(rel.get("weight", 0.0) or 0.0)
        except (TypeError, ValueError):
            pass
        if rel.get("reason"):
            reasons.append(str(rel["reason"]))

    score = min(1.0, round(score, 3))
    candidate.confidence = score

    return {
        "target": candidate.target,
        "scope_status": candidate.scope_status,
        "passive_only": True,
        "relationship_confidence": score,
        "reasons": reasons,
        "requires_confirmation": candidate.scope_status != "IN_SCOPE",
        "active_testing_allowed": candidate.scope_status == "IN_SCOPE",
        "next_step": (
            "active validation may proceed within scope"
            if candidate.scope_status == "IN_SCOPE"
            else "request explicit scope confirmation before active testing"
        ),
    }


def build_paths(primary: str, edges: List[Dict]) -> List[List[str]]:
    graph = {}
    for e in edges or []:
        a, b = e.get("from"), e.get("to")
        if a and b:
            graph.setdefault(a, []).append(b)

    paths = []

    def walk(node, path):
        if len(path) > 8:
            return
        for nxt in graph.get(node, []):
            if nxt in path:
                continue
            p = path + [nxt]
            paths.append(p)
            walk(nxt, p)

    if primary:
        walk(primary, [primary])
    return paths[:100]
