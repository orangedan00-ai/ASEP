
"""Universal Metasploit intelligence for ASEP.

This layer is platform-neutral: Windows is one platform among many.
It matches evidence to module metadata, scores candidates, describes expected
outcomes, and produces a validation plan. It does not execute a module itself.
Consequential execution stays behind ASEP's scope and approval gates.
"""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MetasploitModule:
    name: str
    platforms: List[str]
    services: List[str]
    architectures: List[str] = field(default_factory=list)
    supports_check: bool = True
    expected_outcomes: List[str] = field(default_factory=lambda: ["session"])
    session_types: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class TargetFingerprint:
    target: str
    platform: str = "unknown"
    architecture: str = "unknown"
    services: List[str] = field(default_factory=list)
    versions: Dict[str, str] = field(default_factory=dict)
    evidence: List[Dict] = field(default_factory=list)


def _norm(values):
    return {str(x).strip().lower() for x in values or [] if str(x).strip()}


def match_modules(fp: TargetFingerprint,
                  modules: List[MetasploitModule]) -> List[Dict]:
    """Return scored candidates; no execution is performed."""
    matches = []
    fp_platform = fp.platform.lower()
    fp_arch = fp.architecture.lower()
    fp_services = _norm(fp.services)

    for m in modules:
        platforms = _norm(m.platforms)
        services = _norm(m.services)
        architectures = _norm(m.architectures)

        platform_ok = fp_platform == "unknown" or not platforms or fp_platform in platforms
        service_overlap = fp_services.intersection(services)
        service_ok = not services or bool(service_overlap)
        arch_ok = fp_arch == "unknown" or not architectures or fp_arch in architectures

        if not (platform_ok and service_ok and arch_ok):
            continue

        score = 0.35
        reasons = []
        if platform_ok and fp_platform != "unknown":
            score += 0.20
            reasons.append("platform_match")
        if service_overlap:
            score += min(0.25, 0.10 * len(service_overlap))
            reasons.append("service_match")
        if arch_ok and fp_arch != "unknown":
            score += 0.10
            reasons.append("architecture_match")
        if fp.versions:
            score += 0.05
            reasons.append("version_evidence")

        matches.append({
            "module": m.name,
            "platforms": m.platforms,
            "services": m.services,
            "supports_check": m.supports_check,
            "expected_outcomes": m.expected_outcomes,
            "session_types": m.session_types,
            "prerequisites": m.prerequisites,
            "score": round(min(score, 0.99), 2),
            "reasons": reasons,
            "evidence_required": True,
            "requires_scope_and_approval": True,
            "status": "CANDIDATE",
        })

    return sorted(matches, key=lambda x: x["score"], reverse=True)


def build_validation_plan(fp: TargetFingerprint, candidate: Dict) -> Dict:
    phase = "CHECK" if candidate.get("supports_check") else "EVIDENCE_REVIEW"
    return {
        "target": fp.target,
        "module": candidate["module"],
        "phase": phase,
        "expected_outcomes": candidate.get("expected_outcomes", []),
        "session_types": candidate.get("session_types", []),
        "score": candidate.get("score", 0),
        "requires_scope_and_approval": True,
        "reason": (
            "Fingerprint/service evidence matches this capability candidate; "
            "validate evidence and prerequisites before consequential action."
        ),
    }
