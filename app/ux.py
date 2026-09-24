"""ASEP v2.9 UX data contracts and read-only aggregation helpers.

The module intentionally contains no executor logic. It turns existing evidence,
scope, network-map and session data into stable objects for the UX layer.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .db import connect, list_evidence, list_targets, list_service_inventory, latest_service_scan
from .scope import allowed_targets
from .skill_library import inventory as skill_inventory
from .identity_enrichment import infer_asset_type, normalize_mac


@dataclass
class Target:
    id: str
    address: str
    name: str = ""
    role: str = "unknown"
    state: str = "unknown"
    scope: str = "IN-SCOPE"
    services: int = 0
    ports: list = field(default_factory=list)
    findings: int = 0
    evidence: int = 0
    sessions: int = 0
    source: str = "evidence"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    asset_type: str = "Network Host"
    asset_confidence: str = "low"
    asset_basis: str = "available identity evidence"
    asset_brand: str = ""
    deep_scanned: bool = False
    deep_scan_at: str = ""
    os_name: str = ""
    os_confidence: str = ""


@dataclass
class EvidenceItem:
    id: int
    created_at: str
    evidence_type: str
    target: str
    summary: str = ""
    status: str = "OBSERVED"
    confidence: str = "medium"


@dataclass
class Finding:
    id: str
    title: str
    target: str
    status: str
    confidence: str
    evidence_ids: list[int] = field(default_factory=list)
    detail: str = ""
    source: str = "evidence"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    asset_type: str = "Network Host"
    asset_confidence: str = "low"
    asset_basis: str = "available identity evidence"
    deep_scanned: bool = False
    deep_scan_at: str = ""
    os_name: str = ""
    os_confidence: str = ""


@dataclass
class Recommendation:
    id: str
    title: str
    objective: str
    reason: list[str]
    status: str = "READY"
    confidence: str = "medium"
    action: str = "analyze"
    target: str = ""
    evidence_ids: list[int] = field(default_factory=list)


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {}
    return value or {}


def _evidence_status(evidence_type: str, payload: Any) -> tuple[str, str]:
    p = _json(payload)
    et = (evidence_type or "").lower()
    status = str(p.get("status", "")).upper() if isinstance(p, dict) else ""
    if et == "metasploit_check" and status == "VULNERABLE":
        return "CONFIRMED", "high"
    if et in {"deception_assessment", "deception"}:
        return (status or "UNKNOWN").replace("POSSIBLE_", "POSSIBLE "), "medium"
    if et == "passive_deep_dive":
        return "INDICATOR", "medium"
    if et in {"adaptive_reasoning", "adaptive_replan", "post_session_intelligence"}:
        return "HYPOTHESIS", "medium"
    if et == "metasploit_run":
        return "EXPLOITABLE" if isinstance(p, dict) and p.get("session_id") else "OBSERVED", "high" if p.get("session_id") else "medium"
    return "OBSERVED", "medium"


def evidence_objects(cfg, limit=100) -> list[EvidenceItem]:
    con = connect(cfg)
    rows = con.execute(
        "SELECT id,created_at,evidence_type,target,summary,data FROM evidence ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    con.close()
    return [EvidenceItem(
        id=int(r["id"]), created_at=r["created_at"], evidence_type=r["evidence_type"],
        target=r["target"], summary=r["summary"] or "",
        status=_evidence_status(r["evidence_type"], r["data"])[0],
        confidence=_evidence_status(r["evidence_type"], r["data"])[1],
    ) for r in rows]


def target_objects(cfg, network_data: dict | None = None) -> list[Target]:
    allowed = set(allowed_targets(cfg))
    evid = evidence_objects(cfg, 200)
    by: dict[str, Target] = {}

    # Persisted active-host inventory is the primary source in v2.9.x.
    for row in list_targets(cfg, 500):
        address = str(row.get("address") or "").strip()
        if not address:
            continue
        scope_status = str(row.get("scope_status") or "LOCAL-CANDIDATE")
        md = row.get("metadata") or {}
        identity = md.get("identity") or {} if isinstance(md, dict) else {}
        hostname = str(row.get("name") or md.get("hostname") or identity.get("hostname") or "")
        vendor = str(row.get("vendor") or identity.get("vendor") or "")
        mac = str(row.get("mac") or identity.get("mac_normalized") or "")
        ports = md.get("ports", []) if isinstance(md, dict) else []
        # The persisted service-intelligence DB is the authoritative source after
        # a completed deep scan. This prevents the target inventory from losing
        # service/port data when metadata is stale or the process restarts.
        persisted = list_service_inventory(cfg, target=address, limit=5000, latest_only=True)
        if persisted:
            ports = [{
                "port": str(x.get("port")), "protocol": x.get("protocol"), "state": x.get("state"),
                "service": x.get("service"), "product": x.get("product"), "version": x.get("version"),
                "extrainfo": x.get("extrainfo"), "tunnel": x.get("tunnel"), "method": x.get("method"),
                "confidence": x.get("confidence"), "cpe": x.get("cpe"), "reason": x.get("reason"),
                "detection": "Nmap deep_full / persisted", "scan_id": x.get("scan_id"),
            } for x in persisted]
        observed_ports = [p for p in ports if str(p.get("state", "")).lower() in {"open", "open|filtered"} or p.get("service")]
        inferred = infer_asset_type(vendor, hostname, str(row.get("role") or "unknown"), observed_ports, address)
        osd = md.get("os_detection") if isinstance(md, dict) else {}
        os_matches = (osd or {}).get("matches") or []
        os_name = str(os_matches[0].get("name") or "") if os_matches else ""
        os_conf = str(os_matches[0].get("accuracy") or "") if os_matches else ""
        latest_scan = latest_service_scan(cfg, address) or {}
        deep_scan_persisted = bool(md.get("deep_scan")) or (
            str(latest_scan.get("profile") or "") == "deep_full"
            and str(latest_scan.get("status") or "").upper() == "COMPLETE"
        )
        deep_scan_at = str(md.get("deep_scan_at") or latest_scan.get("finished_at") or "")
        by[address] = Target(
            id=address, address=address, name=hostname or address,
            role=str(row.get("role") or "unknown"), state=str(row.get("state") or "unknown"),
            scope="IN-SCOPE" if scope_status == "IN-SCOPE" or address in allowed else scope_status,
            source=str(row.get("source") or "network-discovery"),
            hostname=hostname, mac=normalize_mac(mac), vendor=vendor,
            services=len(observed_ports), ports=observed_ports,
            asset_type=inferred["type"], asset_confidence=inferred["confidence"], asset_basis=inferred["basis"],
            asset_brand=inferred.get("brand", ""),
            deep_scanned=deep_scan_persisted, deep_scan_at=deep_scan_at,
            os_name=os_name, os_confidence=os_conf,
        )

    # Current network-map data can enrich or surface ephemeral observations.
    if isinstance(network_data, dict):
        for node in network_data.get("nodes", []) or []:
            address = str(node.get("ip") or node.get("id") or "").strip()
            if not address:
                continue
            item = by.setdefault(address, Target(id=address, address=address, name=address))
            item.name = str(node.get("name") or item.name or address)
            item.role = str(node.get("role") or item.role or "unknown")
            item.state = str(node.get("state") or item.state or "unknown")
            item.services = max(item.services, len(node.get("ports", []) or []))
            if node.get("ports"):
                item.ports = node.get("ports", []) or []
            item.hostname = str(node.get("hostname") or item.hostname or "")
            item.mac = normalize_mac(str(node.get("mac") or item.mac or ""))
            item.vendor = str(node.get("vendor") or item.vendor or "")
            inferred = infer_asset_type(item.vendor, item.hostname or item.name, item.role, node.get("ports", []) or [], address)
            item.asset_type, item.asset_confidence, item.asset_basis = inferred["type"], inferred["confidence"], inferred["basis"]
            item.asset_brand = inferred.get("brand", item.asset_brand)
            item.scope = "IN-SCOPE" if address in allowed else item.scope
            if item.source == "evidence":
                item.source = str(node.get("source") or "network-map")

    ignored = {"environment", "wireless", "localhost", "session", "ASEP"}
    for e in evid:
        t = e.target.strip()
        if not t or t in ignored:
            continue
        item = by.setdefault(t, Target(id=t, address=t, name=t))
        item.evidence += 1
        if e.status in {"CONFIRMED", "EXPLOITABLE", "HYPOTHESIS", "INDICATOR"}:
            item.findings += 1
    for item in by.values():
        item.evidence = max(item.evidence, sum(1 for e in evid if e.target == item.address))
    return sorted(by.values(), key=lambda x: x.address)



def intelligence_summary(cfg, network_data: dict | None = None, attack_path: dict | None = None) -> dict:
    """Build deterministic, evidence-first intelligence/readiness summary for the UX.

    This is intentionally local and read-only. It never executes a scan and never
    promotes hypotheses to confirmed findings.
    """
    targets = target_objects(cfg, network_data or {})
    evid = evidence_objects(cfg, 300)
    ap = attack_path or {}

    active = [t for t in targets if str(t.state).lower() in {"up", "active", "online"}] or targets
    identified = [t for t in active if t.mac or t.hostname or t.vendor]
    service_targets = [t for t in active if int(t.services or 0) > 0]

    # Evidence can contain service-validation results even when target metadata has
    # not yet been enriched. Count those targets as having service evidence.
    service_evidence_targets = set()
    for e in evid:
        if e.evidence_type in {"nmap", "target_action", "service_scan", "validate_services"}:
            if e.target and e.target not in {"environment", "localhost", "ASEP"}:
                service_evidence_targets.add(e.target)
    service_covered = {t.address for t in service_targets} | service_evidence_targets

    platform_targets = [
        t for t in active
        if str(t.role or "unknown").lower() not in {"unknown", ""}
        or str(t.asset_type or "Network Host").lower() not in {"network host", ""}
    ]

    confirmed = [f for f in (ap.get("findings", []) if isinstance(ap, dict) else [])
                 if str(f.get("status", "")).strip("[] ").upper() in {"CONFIRMED", "EXPLOITABLE"}]
    paths = ap.get("paths", []) if isinstance(ap, dict) else []

    gaps = []
    if active and len(identified) < len(active):
        gaps.append({"title": "Identity enrichment", "count": len(active)-len(identified), "detail": "Hostnames, MAC/vendor or identity evidence are missing for some active hosts."})
    if active and len(service_covered) < len(active):
        gaps.append({"title": "Service discovery", "count": len(active)-len(service_covered), "detail": "Some active hosts do not yet have service evidence."})
    if active and len(platform_targets) < len(active):
        gaps.append({"title": "Platform / role identification", "count": len(active)-len(platform_targets), "detail": "Some hosts still have insufficient platform or role evidence."})

    discovery_complete = bool(active)
    identity_complete = bool(active) and len(identified) == len(active)
    service_complete = bool(active) and len(service_covered) == len(active)
    platform_complete = bool(active) and len(platform_targets) == len(active)
    analysis_complete = any(e.evidence_type == "intelligence" for e in evid)
    validation_ready = bool(confirmed)
    attack_path_ready = bool(paths) or validation_ready

    if not active:
        next_action = {"title": "Discover the authorized attack surface", "reason": ["No active hosts are currently available to analyze."], "action": "discover", "status": "READY"}
    elif not identity_complete:
        next_action = {"title": "Complete identity enrichment", "reason": [f"{len(active)-len(identified)} active host(s) lack sufficient identity evidence."], "action": "identity", "status": "READY"}
    elif not service_complete:
        next_action = {"title": "Identify services", "reason": [f"{len(active)-len(service_covered)} active host(s) lack service evidence."], "action": "services", "status": "READY"}
    elif not platform_complete:
        next_action = {"title": "Complete platform and role identification", "reason": [f"{len(active)-len(platform_targets)} host(s) need stronger platform/role evidence."], "action": "platform", "status": "READY"}
    elif not analysis_complete:
        next_action = {"title": "Analyze the current environment", "reason": ["Identity, service and platform evidence are available for correlation."], "action": "analyze", "status": "READY"}
    elif not validation_ready:
        next_action = {"title": "Validate candidate findings", "reason": ["Analysis is available, but no confirmed/exploitable finding is recorded."], "action": "validate", "status": "READY"}
    else:
        next_action = {"title": "Review evidence-backed attack paths", "reason": ["Confirmed findings or path candidates are available for controlled validation."], "action": "attack-path", "status": "READY"}

    return {
        "ok": True,
        "environment": {"network": (network_data or {}).get("network") or (network_data or {}).get("cidr") or "unknown", "active_hosts": len(active)},
        "summary": {
            "active_hosts": len(active), "identified_hosts": len(identified), "service_hosts": len(service_covered),
            "platform_hosts": len(platform_targets), "findings_confirmed": len(confirmed), "attack_paths": len(paths),
            "evidence": len(evid),
        },
        "readiness": [
            {"id":"environment", "title":"Environment", "status":"COMPLETE" if active else "READY", "detail":"Local network context and active-host inventory."},
            {"id":"discovery", "title":"Discovery", "status":"COMPLETE" if discovery_complete else "LOCKED", "detail":"Active hosts discovered."},
            {"id":"identity", "title":"Identity", "status":"COMPLETE" if identity_complete else ("NEEDS_MORE_EVIDENCE" if active else "LOCKED"), "detail":"IP, MAC, manufacturer and hostname evidence."},
            {"id":"service", "title":"Service", "status":"COMPLETE" if service_complete else ("NEEDS_MORE_EVIDENCE" if active else "LOCKED"), "detail":"Open service/port evidence."},
            {"id":"platform", "title":"Platform", "status":"COMPLETE" if platform_complete else ("NEEDS_MORE_EVIDENCE" if active else "LOCKED"), "detail":"OS, device type and network role evidence."},
            {"id":"analysis", "title":"Analyze", "status":"COMPLETE" if analysis_complete else ("READY" if platform_complete else "LOCKED"), "detail":"Evidence correlation and knowledge gaps."},
            {"id":"validate", "title":"Validate", "status":"COMPLETE" if validation_ready else ("READY" if analysis_complete else "LOCKED"), "detail":"Confirmed/exploitable findings only after validation."},
            {"id":"attack-path", "title":"Attack Path", "status":"READY" if attack_path_ready else "LOCKED", "detail":"Evidence-backed relationships and candidate paths."},
            {"id":"action", "title":"Action", "status":"READY" if validation_ready else "LOCKED", "detail":"Controlled actions remain scope/policy gated."},
        ],
        "asset_types": _counts([t.asset_type for t in active]),
        "roles": _counts([t.role for t in active]),
        "gaps": gaps,
        "next_best_action": next_action,
    }

def _counts(values):
    out = {}
    for value in values:
        key = str(value or "unknown")
        out[key] = out.get(key, 0) + 1
    return sorted(({"label": k, "count": v} for k, v in out.items()), key=lambda x: (-x["count"], x["label"]))


def finding_objects(cfg, attack_path: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(attack_path, dict):
        for idx, f in enumerate(attack_path.get("findings", []) or [], 1):
            raw = str(f.get("status", "UNKNOWN")).strip("[] ") or "UNKNOWN"
            findings.append(Finding(
                id=f"AP-{idx:04d}", title=str(f.get("title") or "Untitled finding"),
                target=str(f.get("target") or "environment"), status=raw,
                confidence="high" if raw == "CONFIRMED" else ("medium" if raw in {"INDICATOR", "HYPOTHESIS"} else "low"),
                evidence_ids=[int(f["evidence_id"])] if str(f.get("evidence_id", "")).isdigit() else [],
                detail=str(f.get("detail") or ""), source="attack-path",
            ))
    for e in evidence_objects(cfg, 150):
        if e.status not in {"CONFIRMED", "EXPLOITABLE", "HYPOTHESIS", "INDICATOR"}:
            continue
        if e.evidence_type in {"nmap", "wireless", "tool_execution", "network_map"}:
            continue
        findings.append(Finding(
            id=f"EV-{e.id:04d}", title=e.summary or e.evidence_type.replace("_", " ").title(),
            target=e.target, status=e.status, confidence=e.confidence, evidence_ids=[e.id],
            detail=f"Evidence type: {e.evidence_type}", source="evidence",
        ))
    seen = set(); out=[]
    for f in findings:
        key=(f.title,f.target,f.status,tuple(f.evidence_ids))
        if key not in seen:
            seen.add(key); out.append(f)
    return out[:100]


def recommendation_objects(cfg, findings: list[Finding], targets: list[Target]) -> list[Recommendation]:
    recs: list[Recommendation] = []
    high = next((f for f in findings if f.status == "CONFIRMED"), None)
    if high:
        recs.append(Recommendation(
            id="rec-validate-related", title="Validate the confirmed finding boundary",
            objective="Validate confirmed security finding", reason=[
                "A confirmed finding is present in current evidence.",
                "The next step should verify affected scope and related evidence before action.",
            ], confidence="high", action="view-finding", target=high.target, evidence_ids=high.evidence_ids,
        ))
    hyp = next((f for f in findings if f.status == "HYPOTHESIS"), None)
    if hyp:
        recs.append(Recommendation(
            id="rec-validate-hypothesis", title=f"Validate: {hyp.title}",
            objective="Validate an evidence-backed hypothesis", reason=[
                "A hypothesis is supported by collected evidence.",
                "Validation is required before treating it as confirmed.",
            ], confidence=hyp.confidence, action="validate", target=hyp.target, evidence_ids=hyp.evidence_ids,
        ))
    if not recs:
        target = targets[0] if targets else None
        recs.append(Recommendation(
            id="rec-discover", title="Discover the authorized attack surface",
            objective="Understand target attack surface", reason=[
                "No validated finding is available yet.",
                "Start with scoped discovery and evidence collection.",
            ], confidence="medium", action="discover", target=target.address if target else "",
        ))
    return recs[:5]


def dashboard(cfg, network_data=None, attack_path=None, sessions=None, monitor=None) -> dict:
    evid = evidence_objects(cfg, 150)
    targets = target_objects(cfg, network_data)
    findings = finding_objects(cfg, attack_path)
    recs = recommendation_objects(cfg, findings, targets)
    active_sessions = sessions or []
    return {
        "version": (PathVersion := _version(cfg)),
        "scope": allowed_targets(cfg),
        "environment_summary": {
            "network": (network_data or {}).get("network", {}).get("network") if isinstance(network_data, dict) else None,
            "local_ip": (network_data or {}).get("network", {}).get("local_ip") if isinstance(network_data, dict) else None,
            "gateway": (network_data or {}).get("network", {}).get("gateway") if isinstance(network_data, dict) else None,
            "dns_servers": (network_data or {}).get("network", {}).get("dns_servers", []) if isinstance(network_data, dict) else [],
            "interface": (network_data or {}).get("network", {}).get("interface") if isinstance(network_data, dict) else None,
        },
        "network_diagnostic": (network_data or {}).get("network_diagnostic") if isinstance(network_data, dict) else None,
        "metrics": {
            "live_hosts": sum(1 for t in targets if str(t.state).lower() in {"up", "local", "reachable"}),
            "targets": len(targets), "services": sum(t.services for t in targets),
            "findings": len(findings), "sessions": len(active_sessions),
            "paths": len((attack_path or {}).get("paths", []) or []), "evidence": len(evid),
        },
        "targets": [asdict(x) for x in targets[:500]],
        "asset_graph": {
            "status": "READY" if targets else "NO_DATA",
            "nodes": [
                {"id": t.id, "kind": "target", "label": t.address, "type": t.asset_type,
                 "status": t.scope, "detail": f"{t.asset_type} · {t.vendor or 'manufacturer unknown'} · {t.hostname or 'hostname unresolved'}",
                 "hostname": t.hostname, "mac": t.mac, "vendor": t.vendor, "brand": t.asset_brand,
                 "services": t.services, "evidence": t.evidence, "findings": t.findings,
                 "asset_confidence": t.asset_confidence, "asset_basis": t.asset_basis,
                 "x": 12 + (i % 5) * 19, "y": 18 + (i // 5) * 25}
                for i, t in enumerate(targets[:200])
            ], "edges": ((network_data or {}).get("topology", {}).get("edges", []) if isinstance(network_data, dict) else [])
        },
        "findings": [asdict(x) for x in findings[:20]],
        "recommendations": [asdict(x) for x in recs],
        "attack_path": attack_path or {"status":"NO_DATA","nodes":[],"edges":[],"paths":[],"findings":[]},
        "sessions": active_sessions,
        "monitor": monitor or {},
        "pipeline": ["UNDERSTAND","DISCOVER","ANALYZE","VALIDATE","EXPLOIT","POST-EXPLOIT","ACHIEVE"],
    }


def _version(cfg):
    p = cfg["root"] / "VERSION"
    return p.read_text(encoding="utf-8").strip()


def activity(cfg, limit=30):
    con = connect(cfg)
    rows = con.execute("SELECT id,created_at,action,target,status,details FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]
