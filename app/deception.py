"""Decoy/honeypot indicator scoring for authorized assessments.

This detects possible deception; it does not provide monitoring-evasion logic.
"""

def assess(target, fingerprint=None, observations=None):
    fp = fingerprint or {}
    obs = [str(x).lower() for x in (observations or [])]
    indicators = []
    score = 0
    ports = {str(p.get("port")): p for p in fp.get("ports", []) if isinstance(p, dict)}
    # Inconsistency indicators, intentionally conservative.
    if fp.get("os_matches") and any(str(x.get("accuracy", "")) == "100" for x in fp["os_matches"] if isinstance(x, dict)):
        indicators.append("perfect OS match should be validated with service evidence")
        score += 1
    products = [str(p.get("product", "")).lower() for p in ports.values()]
    if len(products) >= 2 and len(set(products)) == 1 and products[0] and "unknown" not in products[0]:
        indicators.append("multiple services expose identical product fingerprint")
        score += 1
    if any("honeypot" in x or "decoy" in x for x in obs):
        indicators.append("explicit deception indicator in collected evidence")
        score += 3
    status = "HIGH_DECOY_INDICATION" if score >= 3 else ("POSSIBLE_DECOY" if score >= 1 else "UNKNOWN")
    return {"target": target, "status": status, "score": score, "indicators": indicators,
            "action": "treat as uncertain infrastructure; validate identity and ownership before escalation"}
