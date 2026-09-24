
"""Objective/evidence-driven ASEP capability routing."""
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class SecurityObjective:
    objective: str
    evidence: List[Dict] = field(default_factory=list)
    environment: List[Dict] = field(default_factory=list)


CAPABILITIES = {
    "recon": "Recon & OSINT",
    "network": "Network Security",
    "web_api": "Web & API Security",
    "identity": "Identity & Directory",
    "cloud": "Cloud Security",
    "wireless": "Wireless Security",
    "linux": "Linux & Unix",
    "windows": "Windows",
    "vuln_research": "Vulnerability Research",
    "exploitation": "Exploitation & Payloads",
    "post_exploitation": "Post-Exploitation",
    "attack_path": "Attack Path & Graph",
    "evidence": "Evidence & Findings",
    "deception": "Deception Detection",
    "reverse_engineering": "Reverse Engineering",
    "malware_analysis": "Malware Analysis",
}


def recommend_capabilities(obj: SecurityObjective) -> List[Dict]:
    raw = (
        obj.objective + " " +
        " ".join(str(x) for x in obj.evidence) + " " +
        " ".join(str(x) for x in obj.environment)
    ).lower()

    scores = {k: 0.0 for k in CAPABILITIES}
    reasons = {k: [] for k in CAPABILITIES}

    scores["recon"] += 0.7
    scores["evidence"] += 0.7
    scores["attack_path"] += 0.7

    rules = {
        "identity": (("domain", "active directory", "kerberos", "identity", "ldap"), 0.9),
        "web_api": (("api", "web", "http", "graphql", "rest", "websocket"), 0.9),
        "wireless": (("wifi", "wireless", "802.11", "rf"), 0.9),
        "cloud": (("cloud", "aws", "azure", "gcp", "iam"), 0.9),
        "linux": (("linux", "unix", "ssh"), 0.7),
        "windows": (("windows", "smb", "winrm", "rdp"), 0.7),
        "vuln_research": (("vulnerability research", "fuzz", "crash", "patch diff"), 0.8),
        "exploitation": (("exploit", "privilege", "shell", "session"), 0.8),
        "post_exploitation": (("post-exploitation", "session", "shell"), 0.8),
        "deception": (("honeypot", "decoy", "deception", "sinkhole"), 0.8),
        "reverse_engineering": (("firmware", "binary", "reverse engineering", "elf", "pe"), 0.8),
        "malware_analysis": (("malware", "sample", "c2", "persistence"), 0.8),
        "network": (("network", "tcp", "udp", "firewall", "vpn", "dns"), 0.6),
    }

    for key, (terms, weight) in rules.items():
        for term in terms:
            if term in raw:
                scores[key] = min(1.0, scores[key] + weight)
                reasons[key].append(term)

    result = []
    for key, score in sorted(scores.items(), key=lambda kv: kv[1], reverse=True):
        if score <= 0:
            continue
        result.append({
            "id": key,
            "name": CAPABILITIES[key],
            "score": round(score, 2),
            "reasons": sorted(set(reasons[key])),
        })
    return result
