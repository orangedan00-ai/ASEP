"""ASEP adaptive, evidence-driven reasoning primitives.

This is deterministic orchestration logic: it generates alternative hypotheses,
weights evidence, and explores attack-path graphs. It does not autonomously
change source code or bypass scope/policy controls.
"""
from collections import defaultdict, deque

STATUSES = ("FACT", "OBSERVATION", "HYPOTHESIS", "CONFIRMED", "EXPLOITABLE", "FALSE_POSITIVE", "UNKNOWN")


def build_hypotheses(target, evidence):
    evidence = evidence or []
    text = " ".join(str(x) for x in evidence).lower()
    out = []
    if "windows" in text or "microsoft" in text:
        out.append({"id": "H1", "hypothesis": "Windows host", "status": "HYPOTHESIS", "next_validation": "OS/service fingerprint"})
    if any(x in text for x in ("445", "smb")):
        out.append({"id": "H2", "hypothesis": "SMB service exposed", "status": "HYPOTHESIS", "next_validation": "SMB protocol/security enumeration"})
    if any(x in text for x in ("80", "443", "http", "https")):
        out.append({"id": "H3", "hypothesis": "HTTP(S) service exposed", "status": "HYPOTHESIS", "next_validation": "HTTP fingerprint and service enumeration"})
    if "decoy" in text or "honeypot" in text:
        out.append({"id": "H4", "hypothesis": "Possible deceptive/decoy host", "status": "HYPOTHESIS", "next_validation": "deception-indicator correlation"})
    if not out:
        out.append({"id": "H0", "hypothesis": "Insufficient evidence for a specific path", "status": "UNKNOWN", "next_validation": "collect baseline service evidence"})
    return {"target": target, "hypotheses": out}


def alternative_paths(nodes, edges, start=None, max_paths=8, max_depth=8):
    graph = defaultdict(list)
    for a, b, label in edges or []:
        graph[a].append((b, label))
    if not start:
        start = nodes[0] if nodes else None
    if not start:
        return []
    results, q = [], deque([(start, [start], [])])
    while q and len(results) < max_paths:
        node, path, labels = q.popleft()
        if len(path) > max_depth:
            continue
        nexts = graph.get(node, [])
        if not nexts:
            if len(path) > 1:
                results.append({"nodes": path, "edges": labels})
            continue
        for nxt, label in nexts:
            if nxt in path:
                continue
            q.append((nxt, path + [nxt], labels + [label]))
    return results


def correlate(target, observations, decoy_assessment=None):
    observations = observations or []
    contradictions = []
    for obs in observations:
        if isinstance(obs, dict) and obs.get("status") == "FALSE_POSITIVE":
            contradictions.append(obs)
    return {
        "target": target,
        "observation_count": len(observations),
        "contradictions": contradictions,
        "decoy_assessment": decoy_assessment or {"status": "UNKNOWN", "score": 0},
        "next_action": "validate contradictory or high-impact hypotheses before exploitation",
    }
